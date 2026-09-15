#!/usr/bin/env python
"""Refuse the commit that puts a File Geodatabase, a shapefile missing its .prj, or a drive letter into git.

The failure this guards is one careless line:

    git add data/

Inside parcels.gdb are 340 files and the largest is 411 kB. Every one of them
clears pre-commit's check-added-large-files at its 500 kB per-file default, so
140 MB of unmergeable binary lands on main and the clone takes eleven minutes a
year later. Three commits earlier somebody staged roads.shp, roads.shx and
roads.dbf but not roads.prj, so every checkout of that shapefile has no CRS and
lands wherever the reader guesses.

check-added-large-files is healthy, maintained and simply the wrong shape for
GIS. It measures one file at a time and has no concept of a directory that is
one dataset, or of a sidecar file set that is only valid complete. This tool
adds those two shapes and nothing else. Credential scanning stays with gitleaks
and detect-secrets, which do it properly.

    python gdbfence.py --self-test
    python gdbfence.py --staged
    python gdbfence.py data/ layers/
    python gdbfence.py --install --apply

Exit codes: 0 clean, 1 findings, 2 a git or install step failed, 64 usage error.
"""

from __future__ import print_function

import argparse
import fnmatch
import io
import os
import re
import subprocess
import sys

# =============================================================================
# CONFIGURATION. Deliberately not flags. Change here, not at the call site.
# =============================================================================

# A dataset over this many bytes is reported. This is the SUM over a .gdb
# directory or a shapefile sidecar set, not a per-file figure. 10 MB is roughly
# where a clone starts to hurt everyone who ever clones.
DEFAULT_MAX_DATASET_SIZE = 10 * 1000 * 1000

# pre-commit's check-added-large-files default, in bytes: --maxkb=500 with a
# 1024 byte kb. Carried here only so the report can state, in numbers, what the
# existing tool was measuring while the dataset sailed past it.
PER_FILE_LIMIT = 500 * 1024

# Directory suffixes that make everything beneath them one dataset. A File
# Geodatabase is a directory of hundreds of .gdbtable and .freelist files that
# are meaningless apart, so it is counted, reported and removed as one thing.
CONTAINER_SUFFIXES = (".gdb", ".gdbindexes")

# Extensions that belong to a shapefile. Seven of them is a normal full set.
SHAPEFILE_SIDECARS = (".shp", ".shx", ".dbf", ".prj", ".cpg", ".sbn", ".sbx",
                      ".qix", ".shp.xml", ".idx", ".ain", ".aih", ".atx")

# The three a shapefile is broken without. .prj is the one that matters: a
# shapefile with no .prj carries no CRS at all, and the reader guesses.
SHAPEFILE_REQUIRED = (".shx", ".dbf", ".prj")

# Things that should essentially never be in a git history. .lock is an active
# ArcGIS editing lock, so committing one commits a private lock nobody else can
# clear.
NEVER_COMMIT = (".gdb", ".sde", ".lock", ".mdb", ".gdbindexes")

# Only these are opened and read for non-portable paths. .lyrx and .mapx are
# CIM documents, which are JSON, and they are where hard-coded drive letters
# hide behind a layer that looks portable in the Pro interface.
TEXT_SUFFIXES = (".lyrx", ".mapx", ".json", ".py", ".pyt", ".txt", ".md",
                 ".yml", ".yaml", ".xml", ".sql", ".cfg", ".ini", ".bat")

# Nothing larger than this is read for text scanning. A 200 MB "json" is not a
# document, and reading it to look for C:\ helps nobody.
TEXT_READ_LIMIT = 4 * 1000 * 1000

# =============================================================================
# End of CONFIGURATION.
# =============================================================================

# Finding codes.
BIG_DATASET = "BIG_DATASET"
INCOMPLETE_SHAPEFILE = "INCOMPLETE_SHAPEFILE"
NEVER_COMMIT_CODE = "NEVER_COMMIT"
NON_PORTABLE_PATH = "NON_PORTABLE_PATH"

# Only these two are fixed by removing the path from history. A shapefile
# missing its .prj is fixed by committing the .prj, and a hard-coded drive
# letter is fixed by editing the line, so offering to rewrite every commit for
# either one is the wrong remedy pointed at a real problem.
REMOVABLE = (BIG_DATASET, NEVER_COMMIT_CODE)

# An absolute drive letter: C:\Users or C:/Users, escaped or not. The word
# boundary keeps https:// and the like out of it.
DRIVE_RE = re.compile(r"\b[A-Za-z]:[\\/]")

# A UNC share. Written \\gisfiles\parcels in a .py and \\\\gisfiles\\\\parcels
# once JSON has escaped it, so the pattern has to survive both spellings.
#
# The leading group is the guard: a UNC path only counts at the START of a
# path, after a quote, an equals sign or whitespace. Without it, the CIM
# spelling of a RELATIVE path, "..\\data\\parcels.gdb", contains \\data\ and
# every portable layer file in the repository is reported as non-portable.
UNC_RE = re.compile(r"""(?:^|[\s"'=(\[,:])(\\{2,4}[A-Za-z0-9._$-]+\\)""")

# A path made only of these characters needs no quoting in the printed
# filter-repo command. Anything else is double quoted. GIS paths have spaces in
# them as a matter of routine, and an unquoted --path C:/GIS Data/parcels.gdb is
# two arguments, neither of which filter-repo would ever find.
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/@=+-]+$")


class Finding(object):
    """One thing wrong with one dataset, plus the path filter-repo would take."""

    def __init__(self, code, path, message, remedy_path=None):
        self.code = code
        self.path = path
        self.message = message
        # What git filter-repo needs, which is the .gdb directory rather than
        # the 340 files inside it.
        self.remedy_path = remedy_path or path

    def __repr__(self):
        return "Finding(%s, %r)" % (self.code, self.path)


# ----------------------------------------------------------------- pure core

def normalize(path):
    """One spelling for a path, so grouping and ignoring agree with each other.

    git reports forward slashes on every platform. Windows hands us backslashes.
    Everything below assumes the git spelling.
    """
    if path is None:
        raise ValueError("path cannot be None")
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.rstrip("/")


def splitext_gis(path):
    """Split an extension, treating roads.shp.xml as one .shp.xml sidecar."""
    if path.lower().endswith(".shp.xml"):
        return path[:-8], ".shp.xml"
    return os.path.splitext(path)


def dataset_of(path):
    """Return (dataset key, kind) for a file path. The whole classifier.

    Kinds are "gdb" for anything under a container directory, "shapefile" for a
    sidecar member, and "file" for everything else.

    Only ANCESTOR components are tested for a container suffix. That is the
    defect this shape exists to prevent: parcels.gdb.zip is a single file that
    happens to have .gdb in its name, and a substring test turns it into a
    directory that is never walked and a dataset that is never reported.
    """
    p = normalize(path)
    parts = p.split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower().endswith(CONTAINER_SUFFIXES):
            return "/".join(parts[:i + 1]), "gdb"
    stem, ext = splitext_gis(p)
    if ext.lower() in SHAPEFILE_SIDECARS:
        return stem, "shapefile"
    return p, "file"


def ignored(path, patterns):
    """True when the path, or any directory above it, matches an --ignore glob."""
    p = normalize(path)
    parts = p.split("/")
    prefixes = ["/".join(parts[:i + 1]) for i in range(len(parts))]
    # Both sides are folded, and fnmatchcase is used rather than fnmatch, which
    # calls os.path.normcase and therefore folds case on Windows and not on
    # Linux. Without this, --ignore "vendor/*" skips VENDOR/roads.shp under
    # ArcGIS Pro's Python and audits it under a plain python3, so the same
    # repository gets two verdicts depending on who ran the hook.
    for pattern in patterns:
        pat = normalize(pattern).lower()
        for candidate in prefixes:
            cand = candidate.lower()
            if fnmatch.fnmatchcase(cand, pat) or fnmatch.fnmatchcase(
                    cand.split("/")[-1], pat):
                return True
    return False


def group(entries, ignore=()):
    """Collapse (path, size) tuples into datasets keyed by dataset_of().

    Returns key -> {"kind", "files", "total", "exts"}.
    """
    datasets = {}
    for path, size in entries:
        if size is None or size < 0:
            raise ValueError("size must be a non-negative integer, got %r for %r"
                             % (size, path))
        p = normalize(path)
        if ignored(p, ignore):
            continue
        key, kind = dataset_of(p)
        ds = datasets.setdefault(key, {"kind": kind, "files": [], "total": 0,
                                       "exts": set()})
        ds["files"].append((p, size))
        ds["total"] += size
        ds["exts"].add(splitext_gis(p)[1].lower())
    return datasets


def human_size(n):
    """Bytes as the number a person would say out loud."""
    if n >= 1000000:
        return "%.1f MB" % (n / 1000000.0)
    if n >= 1000:
        return "%.1f kB" % (n / 1000.0)
    return "%d B" % n


def parse_size(text):
    """Accept 10MB, 500kB, 2.5M or a plain byte count. Decimal units."""
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?)[bB]?\s*$", str(text))
    if not m:
        raise ValueError("cannot read a size from %r, try 10MB or 10000000"
                         % (text,))
    scale = {"": 1, "k": 1000, "m": 1000000, "g": 1000000000}[m.group(2).lower()]
    return int(float(m.group(1)) * scale)


def audit(entries, max_dataset_size=DEFAULT_MAX_DATASET_SIZE, ignore=(),
          per_file_limit=PER_FILE_LIMIT):
    """Findings for a list of (path, size) tuples. No disk, no git, no network.

    Everything this tool decides is decided here, which is why the self-test can
    check a 340 file geodatabase without one existing.
    """
    if max_dataset_size < 0:
        raise ValueError("--max-dataset-size cannot be negative")
    if per_file_limit < 0:
        raise ValueError("the per-file limit cannot be negative")

    datasets = group(entries, ignore)
    findings = []

    for key in sorted(datasets):
        ds = datasets[key]

        # Never-commit first, because it is true whatever the size says.
        if ds["kind"] == "gdb" and key.lower().endswith(NEVER_COMMIT):
            findings.append(Finding(
                NEVER_COMMIT_CODE, key,
                "a geodatabase directory (%d file(s) here) is binary and "
                "unmergeable, keep it out of git entirely" % len(ds["files"])))
        elif ds["kind"] == "file" and key.lower().endswith(NEVER_COMMIT):
            findings.append(Finding(
                NEVER_COMMIT_CODE, key,
                "%s files should never be committed" % splitext_gis(key)[1]))

        # Dataset-shaped size. The per-file figure rides along in the message
        # because the whole point is that per-file checking saw nothing wrong.
        if ds["total"] > max_dataset_size:
            largest = max(size for _, size in ds["files"])
            note = ""
            if largest <= per_file_limit:
                note = (", and its largest single file is %s, under the %s "
                        "per-file rule" % (human_size(largest),
                                           human_size(per_file_limit)))
            findings.append(Finding(
                BIG_DATASET, key,
                "one dataset of %d file(s) totalling %s, over the %s limit%s"
                % (len(ds["files"]), human_size(ds["total"]),
                   human_size(max_dataset_size), note)))

        # A shapefile is only a dataset when it is complete.
        if ds["kind"] == "shapefile" and ".shp" in ds["exts"]:
            missing = [e for e in SHAPEFILE_REQUIRED if e not in ds["exts"]]
            if missing:
                findings.append(Finding(
                    INCOMPLETE_SHAPEFILE, key + ".shp",
                    "incomplete shapefile, missing %s%s" % (
                        " ".join(missing),
                        ". Without .prj it carries no CRS and the reader guesses"
                        if ".prj" in missing else ""),
                    remedy_path=key + ".shp"))

    return findings


def scan_text(path, text):
    """Findings for the CONTENT of one text or CIM document.

    Kept apart from audit() so the size and completeness rules never need a file
    to be readable, and so this one is testable against a string literal.
    """
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        m = DRIVE_RE.search(line)
        if m:
            findings.append(Finding(
                NON_PORTABLE_PATH, path,
                "line %d holds the absolute path \"%s\", which only resolves on "
                "the machine that wrote it" % (line_no, m.group(0))))
            continue
        m = UNC_RE.search(line)
        if m:
            findings.append(Finding(
                NON_PORTABLE_PATH, path,
                "line %d holds the UNC path \"%s\", which only resolves inside one "
                "network" % (line_no, m.group(1))))
    return findings


def removable_paths(findings):
    """The dataset paths whose problem removal actually solves."""
    return sorted(set(f.remedy_path for f in findings if f.code in REMOVABLE))


def quote_path(path):
    """The path as one shell argument, quoted only when it has to be.

    Double quotes rather than single, because this line gets pasted into
    cmd.exe at least as often as into bash.
    """
    if SAFE_PATH_RE.match(path):
        return path
    if '"' in path or "\n" in path:
        # No quoting survives either character in both shells. A loud refusal
        # beats printing a destructive command that means a different path.
        raise ValueError("cannot write a shell-safe command for %r" % (path,))
    return '"%s"' % path


def filter_repo_command(paths):
    """The exact command that removes these paths from every commit.

    Printed, never run. It rewrites every hash in the repository and every
    collaborator has to re-clone, so the person who owns that decision is the
    person reading the output, not this tool.
    """
    if not paths:
        # --invert-paths with no --path at all is a command whose meaning
        # depends on the filter-repo version, and every reading of it is
        # destructive. Never print one.
        raise ValueError("no paths to remove, so there is no command to print")
    args = " ".join("--path %s" % quote_path(p) for p in sorted(set(paths)))
    return "git filter-repo --invert-paths --force %s" % args


def hook_script(tool_path):
    """The plain git pre-commit hook, as text."""
    return ("#!/bin/sh\n"
            "# Installed by gdbfence --install. Delete this file to remove it.\n"
            "exec python %s --staged\n" % tool_path)


def precommit_entry(tool_path):
    """The .pre-commit-config.yaml block, as text."""
    return ("-   repo: local\n"
            "    hooks:\n"
            "    -   id: gdbfence\n"
            "        name: gdbfence\n"
            "        entry: python %s --staged\n"
            "        language: system\n"
            "        pass_filenames: false\n" % tool_path)


def describe(findings):
    """Render findings as the lines the CLI prints."""
    out = []
    for f in findings:
        out.append("  %s  %s" % (f.code, f.path))
        out.append("      %s" % f.message)
    out.append("VERDICT: %s" % ("REFUSE" if findings else "CLEAN"))
    return out


# ------------------------------------------------------------------------ io

def git(args, cwd=None):
    """Run a read-only git command. Returns stdout, or None when git says no."""
    try:
        out = subprocess.check_output(["git"] + args, cwd=cwd,
                                      stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.decode("utf-8", "replace")


def staged_entries():
    """(path, size) for every file git has staged. Sizes come from the index.

    git lists the files inside parcels.gdb individually, which is exactly the
    input the core wants: the core does the grouping.

    -z is not optional. Without it core.quotePath, which is on by default,
    prints a path holding any non-ASCII character as "donn\303\251es.shp",
    quotes and all. That spelling matches nothing on disk and nothing in the
    index, so a 20 MB donnees.shp was dropped from the audit in silence.
    """
    out = git(["diff", "--cached", "--name-only", "-z",
               "--diff-filter=ACMR"])
    if out is None:
        return None
    entries = []
    for path in out.split("\0"):
        if not path:
            continue
        size = git(["cat-file", "-s", ":" + path])
        if size is not None and size.strip().isdigit():
            entries.append((path, int(size.strip())))
        elif os.path.isfile(path):
            entries.append((path, os.path.getsize(path)))
    return entries


def walk_entries(paths):
    """(path, size) for the command line arguments, walking any directory.

    main refuses a path that does not exist before calling this, so os.walk
    over a missing directory yielding nothing is not a silent pass here.
    """
    entries = []
    for arg in paths:
        if os.path.isfile(arg):
            entries.append((arg, os.path.getsize(arg)))
            continue
        for root, dirs, files in os.walk(arg):
            if ".git" in dirs:
                dirs.remove(".git")
            for name in files:
                full = os.path.join(root, name)
                try:
                    entries.append((full, os.path.getsize(full)))
                except OSError:
                    pass
    return entries


def document_text(path, size, staged=False):
    """The text of a document worth scanning, or None. Never raises on binary.

    With --staged this reads the INDEX, not the working tree. A hook that reads
    the working tree is walked straight past: stage the .lyrx with the drive
    letter in it, fix the file afterwards, and the hook blesses the fixed copy
    while git commits the broken one. Verified by doing exactly that.
    """
    if size > TEXT_READ_LIMIT:
        return None
    if not normalize(path).lower().endswith(TEXT_SUFFIXES):
        return None
    if staged:
        text = git(["show", ":" + path])
    else:
        try:
            with open(path, "rb") as fh:
                text = fh.read().decode("utf-8", "replace")
        except (OSError, IOError):
            return None
    if text is None or "\x00" in text:
        return None
    return text


def in_history(path):
    """True when git already has this path in a commit."""
    out = git(["log", "--oneline", "-1", "--", path])
    return bool(out and out.strip())


def install(tool_path, apply_it):
    """Write the git pre-commit hook. Prints the pre-commit entry either way."""
    print("pre-commit-hooks entry for .pre-commit-config.yaml:")
    print("")
    print(precommit_entry(tool_path))

    hook_dir = git(["rev-parse", "--git-path", "hooks"])
    if hook_dir is None:
        print("error: not inside a git repository, so there is no hook to "
              "write. The entry above still works.", file=sys.stderr)
        return 2
    hook_dir = hook_dir.strip()
    hook = normalize(os.path.join(hook_dir, "pre-commit"))

    if os.path.exists(hook):
        print("error: %s already exists. Refusing to overwrite it. Add this "
              "line to it yourself:\n  python %s --staged"
              % (hook, tool_path), file=sys.stderr)
        return 2
    if not apply_it:
        print("Would write %s. Re-run with --apply to write it." % hook)
        return 0
    try:
        if not os.path.isdir(hook_dir):
            os.makedirs(hook_dir)
        with open(hook, "w") as fh:
            fh.write(hook_script(tool_path))
        os.chmod(hook, 0o755)
    except (OSError, IOError) as exc:
        print("error: could not write %s: %s" % (hook, exc), file=sys.stderr)
        return 2
    print("Wrote %s" % hook)
    print("It runs %s from the repository root, so keep a copy there."
          % tool_path)
    return 0


# ------------------------------------------------------------------ self-test

def self_test():
    """Assertions over the decision core. No git, no disk, no network."""
    passed = [0]
    failed = []

    def check(cond, label):
        if cond:
            passed[0] += 1
            print("PASS  %s" % label)
        else:
            failed.append(label)
            print("FAIL  %s" % label)

    def raises(fn, label):
        try:
            fn()
        except ValueError:
            check(True, label)
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)

    def codes(findings):
        return [f.code for f in findings]

    print("gdbfence self-test: no git, no disk, no network")
    print("-" * 68)

    # ---- the classifier
    check(dataset_of("data/parcels.gdb/a00000001.gdbtable")
          == ("data/parcels.gdb", "gdb"),
          "a file under a .gdb belongs to that .gdb")
    check(dataset_of("data/parcels.gdb/idx/a.gdbindexes/x.bin")[0]
          == "data/parcels.gdb",
          "the outermost container wins over a nested one")
    check(dataset_of("roads.shp") == ("roads", "shapefile"),
          "a .shp is a shapefile dataset keyed by its stem")
    check(dataset_of("roads.prj")[0] == "roads",
          "a .prj groups with the .shp of the same stem")
    check(dataset_of("roads.shp.xml")[0] == "roads",
          "roads.shp.xml groups with roads, not with a dataset called roads.shp")
    check(dataset_of("notes.md") == ("notes.md", "file"),
          "an ordinary file is its own dataset")
    check(dataset_of("data\\parcels.gdb\\a.gdbtable")[0] == "data/parcels.gdb",
          "a windows path is read the same as a git path")
    check(dataset_of("DATA/PARCELS.GDB/A.GDBTABLE")[0] == "DATA/PARCELS.GDB",
          "an uppercase .GDB is still a container directory")
    check(dataset_of("GIS Data/tax parcels.gdb/a.gdbtable")[0]
          == "GIS Data/tax parcels.gdb",
          "a path with spaces in it groups like any other")

    # ---- THE PINNED DEFECT: .gdb inside a name is not a .gdb directory
    check(dataset_of("archive/parcels.gdb.zip")
          == ("archive/parcels.gdb.zip", "file"),
          "parcels.gdb.zip is ONE FILE, never walked as a directory  <-- pinned defect")
    d = group([("archive/parcels.gdb.zip", 50000000)])
    check(len(d) == 1 and d["archive/parcels.gdb.zip"]["kind"] == "file",
          "the zip forms a single one-file dataset  <-- pinned defect")
    f = audit([("archive/parcels.gdb.zip", 50000000)])
    check(NEVER_COMMIT_CODE not in codes(f),
          "the zip is not reported as a geodatabase  <-- pinned defect")
    check(BIG_DATASET in codes(f), "the zip is still reported for its own size")

    # ---- the headline: dataset-shaped size against per-file size
    gdb = [("data/parcels.gdb/a%08d.gdbtable" % i, 411000) for i in range(340)]
    d = group(gdb)
    check(len(d) == 1, "340 files under one .gdb group into ONE dataset")
    check(d["data/parcels.gdb"]["total"] == 139740000,
          "340 files of 411 kB is ONE 139.7 MB dataset, not 340 small files")
    check(max(s for _, s in gdb) < PER_FILE_LIMIT,
          "every one of those 411 kB files passes the 500 kB per-file rule")
    f = audit(gdb)
    big = [x for x in f if x.code == BIG_DATASET]
    check(len(big) == 1,
          "the 139.7 MB dataset is refused while all 340 files pass "
          "check-added-large-files")
    check("139.7 MB" in big[0].message, "the report states the dataset total")
    check("411.0 kB" in big[0].message and "512.0 kB" in big[0].message,
          "the report states the largest file and the per-file rule it passed")
    check(big[0].path == "data/parcels.gdb",
          "the finding names the .gdb, not one of its 340 files")
    check(NEVER_COMMIT_CODE in codes(f), "the .gdb is also refused outright")

    # ---- the size rule itself
    check(BIG_DATASET not in codes(audit([("data/small.gdb/x", 9000000)])),
          "a 9 MB geodatabase is under the 10 MB limit")
    check(BIG_DATASET not in codes(audit([("big.tif", 10000000)])),
          "exactly the limit is allowed, the limit is inclusive")
    check(BIG_DATASET in codes(audit([("big.tif", 10000001)])),
          "one byte over the limit is reported")
    check(BIG_DATASET in codes(audit([("big.tif", 2000000)],
                                     max_dataset_size=1000000)),
          "a lower --max-dataset-size reports what the default allowed")
    check(codes(audit([("small.csv", 10)])) == [],
          "a small ordinary file produces nothing")
    f = audit([("imagery/lidar.tif", 80000000)])
    check(codes(f) == [BIG_DATASET],
          "a single 80 MB GeoTIFF is one oversized dataset")
    check("per-file rule" not in f[0].message,
          "a file that is ITSELF over the per-file limit is never described as "
          "passing it  <-- pinned defect")

    # ---- the shapefile sidecar set
    part = [("roads.shp", 100), ("roads.shx", 10), ("roads.dbf", 50)]
    f = audit(part)
    check(codes(f) == [INCOMPLETE_SHAPEFILE],
          "a 3 of 7 shapefile set is INCOMPLETE")
    check(".prj" in f[0].message, "the report names the missing .prj")
    check("CRS" in f[0].message, "the report says why .prj is the one that matters")
    check(f[0].path == "roads.shp", "the finding is reported against the .shp")
    full = part + [("roads.prj", 5), ("roads.cpg", 5), ("roads.sbn", 5),
                   ("roads.sbx", 5)]
    check(codes(audit(full)) == [], "a complete 7 file shapefile produces nothing")
    f = audit([("roads.shp", 1), ("roads.prj", 1), ("roads.dbf", 1)])
    check(codes(f) == [INCOMPLETE_SHAPEFILE],
          "a set with a .prj but no .shx is still incomplete")
    check(".shx" in f[0].message and ".prj" not in f[0].message,
          "only the extensions actually missing are named")
    check(codes(audit([("roads.prj", 5), ("roads.dbf", 5)])) == [],
          "sidecars with no .shp are not judged as a shapefile")
    check(codes(audit([("ROADS.SHP", 1), ("ROADS.SHX", 1), ("ROADS.DBF", 1),
                       ("ROADS.PRJ", 1)])) == [],
          "an uppercase but complete shapefile set produces nothing")
    check(codes(audit([("ROADS.SHP", 1), ("ROADS.SHX", 1), ("ROADS.DBF", 1)]))
          == [INCOMPLETE_SHAPEFILE],
          "an uppercase set missing its .PRJ is still incomplete")
    # A characterisation test, not a wish: extensions are matched without
    # regard to case, the name before the extension is not, and the README
    # says so under Limits.
    check(codes(audit([("ROADS.SHP", 1), ("ROADS.SHX", 1), ("ROADS.DBF", 1),
                       ("roads.prj", 1)])) == [INCOMPLETE_SHAPEFILE],
          "sidecars that disagree about the case of the NAME are two datasets")
    check(codes(audit([("roads.shp", 6000000), ("roads.dbf", 6000000),
                       ("roads.shx", 10), ("roads.prj", 10)])) == [BIG_DATASET],
          "a shapefile's size is the sum of its sidecars")
    check(codes(audit([("roads.shp", 6000000), ("roads.dbf", 6000000)]))
          == [BIG_DATASET, INCOMPLETE_SHAPEFILE],
          "one shapefile can be too big and incomplete at the same time")

    # ---- ignoring
    check(codes(audit(full, ignore=("*.shp",))) == [],
          "an --ignore glob drops the file it matches")
    vendor = [("vendor/" + p, s) for p, s in full]
    check(codes(audit(vendor, ignore=("vendor/*",))) == [],
          "a complete shapefile under an ignored path produces nothing")
    check(codes(audit([("vendor/roads.shp", 1)], ignore=("vendor/*",))) == [],
          "an incomplete shapefile under an ignored path produces nothing either")
    check(codes(audit(gdb, ignore=("data/parcels.gdb",))) == [],
          "ignoring the .gdb directory drops all 340 files under it")
    check(ignored("data/parcels.gdb/x.gdbtable", ["*.gdb"]),
          "a glob matches a directory above the file")
    check(not ignored("data/roads.shp", ["vendor/*"]),
          "an unrelated path is not ignored")
    check(ignored("VENDOR/roads.shp", ["vendor/*"]),
          "--ignore folds case the same way on every platform  <-- pinned defect")
    check(ignored("data/ROADS.SHP", ["*.shp"]),
          "an uppercase file matches a lowercase glob  <-- pinned defect")
    check(codes(audit([("VENDOR/roads.shp", 1)], ignore=("vendor/*",))) == [],
          "the case-folded ignore reaches audit, not only ignored()")

    # ---- things that should never be committed
    check(codes(audit([("conn.sde", 10)])) == [NEVER_COMMIT_CODE],
          "a .sde connection file is refused")
    check(codes(audit([("parcels.gdb.lock", 10)])) == [NEVER_COMMIT_CODE],
          "a .lock file is refused")
    check(codes(audit([("old/parcels.mdb", 10)])) == [NEVER_COMMIT_CODE],
          "a personal geodatabase .mdb is refused")
    check(codes(audit([("notes.txt", 10)])) == [],
          "an ordinary text file is not refused")

    # ---- non-portable paths in text and CIM documents
    cim = ('{"dataConnection": {"workspaceConnectionString": '
           '"DATABASE=C:\\\\GIS\\\\parcels.gdb"}}')
    f = scan_text("parcels.lyrx", cim)
    check(codes(f) == [NON_PORTABLE_PATH],
          "a CIM document with an absolute user path is non-portable")
    check("line 1" in f[0].message, "the report gives the line number")
    rel = ('{"dataConnection": {"workspaceConnectionString": '
           '"DATABASE=..\\\\data\\\\parcels.gdb"}}')
    check(scan_text("parcels.lyrx", rel) == [],
          "the same CIM document with a relative path is fine  <-- pinned defect")
    check(scan_text("etl.py", 'p = "..\\\\data\\\\roads.shp"') == [],
          "an escaped relative path is not a UNC share  <-- pinned defect")
    check(codes(scan_text("etl.py", 'ws = r"D:/gis/staging"'))
          == [NON_PORTABLE_PATH],
          "a forward slash drive letter is caught too")
    check(codes(scan_text("etl.py", 'ws = r"\\\\gisfiles\\parcels\\current"'))
          == [NON_PORTABLE_PATH],
          "a UNC share path is non-portable")
    check(codes(scan_text("etl.py", '{"p": "\\\\\\\\gisfiles\\\\\\\\parcels"}'))
          == [NON_PORTABLE_PATH],
          "a UNC path survives JSON escaping")
    check(scan_text("readme.md", "see https://example.org/a") == [],
          "a URL is not a drive letter")
    check(scan_text("etl.py", 'ws = "./data/parcels.gdb"') == [],
          "a relative workspace is fine")
    check(len(scan_text("a.py", 'x = "C:/a"\ny = 1\nz = "E:/b"')) == 2,
          "every offending line is reported, not just the first")

    # ---- sizes in and out
    check(parse_size("10MB") == 10000000, "10MB parses to ten million bytes")
    check(parse_size("500kB") == 500000, "500kB parses")
    check(parse_size("2.5M") == 2500000, "a fractional size parses")
    check(parse_size("4096") == 4096, "a bare byte count parses")
    check(human_size(139740000) == "139.7 MB", "139740000 bytes reads as 139.7 MB")
    check(human_size(411000) == "411.0 kB", "411000 bytes reads as 411.0 kB")
    check(human_size(12) == "12 B", "a tiny size stays in bytes")

    # ---- the remedy is printed, never run
    check(filter_repo_command(["data/parcels.gdb"])
          == "git filter-repo --invert-paths --force --path data/parcels.gdb",
          "the filter-repo command names the .gdb directory, not its files")
    check("--path a --path b" in filter_repo_command(["b", "a", "b"]),
          "repeated paths are de-duplicated and sorted into one command")
    check(filter_repo_command(["GIS Data/tax parcels.gdb"])
          == 'git filter-repo --invert-paths --force '
             '--path "GIS Data/tax parcels.gdb"',
          "a path with a space is quoted into ONE argument  <-- pinned defect")
    check(quote_path("data/parcels.gdb") == "data/parcels.gdb",
          "a plain path is left unquoted")
    check(quote_path("data/a&b.gdb") == '"data/a&b.gdb"',
          "an ampersand is quoted, it ends the line in cmd.exe otherwise")
    raises(lambda: filter_repo_command([]),
           "nothing to remove prints no command at all  <-- pinned defect")
    raises(lambda: quote_path('data/say "hi".gdb'),
           "a path holding a double quote is refused, not mis-quoted")
    check(removable_paths(audit(gdb)) == ["data/parcels.gdb"],
          "a bloated .gdb is offered to filter-repo once, not 340 times")
    check(removable_paths(audit(part)) == [],
          "an incomplete shapefile is NOT offered to filter-repo, you add the .prj")
    check(removable_paths(scan_text("a.lyrx", 'p = "C:/gis"')) == [],
          "a hard-coded drive letter is NOT offered to filter-repo, you edit the line")

    # ---- input validation
    raises(lambda: normalize(None), "a null path raises")
    raises(lambda: audit([("a.tif", -1)]), "a negative size raises")
    raises(lambda: audit([("a.tif", None)]), "a null size raises")
    raises(lambda: audit([("a.tif", 1)], max_dataset_size=-1),
           "a negative --max-dataset-size raises")
    raises(lambda: parse_size("ten megabytes"), "an unreadable size raises")

    # ---- rendering
    check(describe([])[-1] == "VERDICT: CLEAN", "no findings renders CLEAN")
    check(describe(audit(gdb))[-1] == "VERDICT: REFUSE",
          "findings render REFUSE last")

    # ---- argument handling. GDBFENCE_MAX_DATASET_SIZE is taken out of the
    # environment first: it supplies the default for --max-dataset-size, so a
    # developer who exports it once used to see this self-test fail.
    saved_env = os.environ.pop("GDBFENCE_MAX_DATASET_SIZE", None)
    try:
        a = _parse([])
        check(a.apply is False, "--apply defaults to OFF")
        check(a.install is False, "--install defaults to OFF")
        check(a.staged is False, "--staged defaults to OFF")
        check(a.no_history is False,
              "the read-only history check is ON by default")
        check(a.max_dataset_size == DEFAULT_MAX_DATASET_SIZE,
              "--max-dataset-size defaults to the configured value")
        check(a.ignore == [], "--ignore defaults to empty")
        check(_parse(["--self-test"]).self_test, "--self-test parses")
        check(_parse(["--staged"]).staged is True, "--staged is read")
        check(_parse(["--max-dataset-size", "1MB"]).max_dataset_size == 1000000,
              "--max-dataset-size is read and parsed")
        check(_parse(["--ignore", "vendor/*", "--ignore", "*.tif"]).ignore
              == ["vendor/*", "*.tif"], "--ignore is read and repeatable")
        check(_parse(["data", "layers"]).paths == ["data", "layers"],
              "bare paths are read")
        check(_parse(["--install", "--apply"]).apply is True, "--apply is read")
        check(_parse(["--no-history"]).no_history is True, "--no-history is read")

        os.environ["GDBFENCE_MAX_DATASET_SIZE"] = "25MB"
        check(_parse([]).max_dataset_size == 25000000,
              "GDBFENCE_MAX_DATASET_SIZE is read and parsed  <-- pinned defect")
        check(_parse(["--max-dataset-size", "1MB"]).max_dataset_size == 1000000,
              "the flag beats the environment variable")
    finally:
        os.environ.pop("GDBFENCE_MAX_DATASET_SIZE", None)
        if saved_env is not None:
            os.environ["GDBFENCE_MAX_DATASET_SIZE"] = saved_env

    # ---- the exit codes, with stderr muted so the report stays readable
    real_stderr, sys.stderr = sys.stderr, io.StringIO()
    try:
        check(main([]) == 64, "no paths and no --staged is a usage error")
        check(main(["no-such-path-4f2a1c"]) == 64,
              "a path that does not exist is a usage error, not a clean "
              "pass  <-- pinned defect")
    finally:
        sys.stderr = real_stderr

    # ---- the hook text it would install
    check(hook_script("gdbfence.py").startswith("#!/bin/sh"),
          "the git hook is a shell script")
    check("--staged" in hook_script("gdbfence.py"),
          "the git hook runs the tool against the staged files")
    check("language: system" in precommit_entry("gdbfence.py"),
          "the pre-commit entry needs no install step")

    print("-" * 68)
    total = passed[0] + len(failed)
    if failed:
        print("%d assertions, %d failed" % (total, len(failed)))
        for f in failed:
            print("  FAILED: %s" % f)
        return 1
    print("%d assertions, 0 failed" % total)
    return 0


# ----------------------------------------------------------------------- cli

def _parse(argv):
    ap = argparse.ArgumentParser(
        prog="gdbfence.py",
        description="Refuse the commit that puts a File Geodatabase, a "
                    "shapefile missing its .prj, or a drive letter into git.",
        epilog="Nothing is written without --apply, and the filter-repo "
               "command is printed, never run.",
    )
    ap.add_argument("paths", nargs="*", help="files or directories to audit")
    ap.add_argument("--staged", action="store_true",
                    help="audit git's staged file list instead of PATHS")
    ap.add_argument("--max-dataset-size", dest="max_dataset_size",
                    type=parse_size,
                    default=os.environ.get("GDBFENCE_MAX_DATASET_SIZE",
                                           DEFAULT_MAX_DATASET_SIZE),
                    help="largest allowed total for ONE dataset, summed over a "
                         ".gdb directory or a shapefile sidecar set "
                         "(default 10MB). Env: GDBFENCE_MAX_DATASET_SIZE")
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob. Repeatable.")
    ap.add_argument("--no-history", dest="no_history", action="store_true",
                    help="skip the read-only git check for paths already in "
                         "history, which is what prints the filter-repo command")
    ap.add_argument("--install", action="store_true",
                    help="print the pre-commit-hooks entry and write a plain "
                         "git pre-commit hook. Needs --apply to write.")
    ap.add_argument("--apply", action="store_true",
                    help="write the hook file. Without this nothing is written.")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run the offline assertions and exit")
    # argparse runs type= over a default that is still a string, so the value
    # from GDBFENCE_MAX_DATASET_SIZE goes through parse_size as well, and an
    # unreadable one is a usage error rather than a traceback.
    return ap.parse_args(argv)


def main(argv=None):
    args = _parse(sys.argv[1:] if argv is None else argv)

    if args.self_test:
        return self_test()

    if args.install:
        return install(os.path.basename(os.path.abspath(__file__)), args.apply)

    if args.staged:
        entries = staged_entries()
        if entries is None:
            print("error: git could not list staged files. Run this inside a "
                  "git repository, or pass paths instead.", file=sys.stderr)
            return 2
        source = "git's staged files"
    elif args.paths:
        # A path that does not exist is a usage error, not a clean audit. A
        # typo, or a data directory somebody renamed, would otherwise leave a
        # CI step reporting CLEAN over nothing at all, for as long as it takes
        # anyone to notice.
        missing = [p for p in args.paths if not os.path.exists(p)]
        if missing:
            print("error: no such file or directory: %s" % ", ".join(missing),
                  file=sys.stderr)
            return 64
        entries = walk_entries(args.paths)
        source = "%d path(s) on the command line" % len(args.paths)
    else:
        print("error: pass paths to audit, or --staged. Use --self-test to "
              "verify the tool without a repository.", file=sys.stderr)
        return 64

    print("gdbfence: %d file(s) from %s" % (len(entries), source))
    findings = audit(entries, args.max_dataset_size, args.ignore)

    for path, size in entries:
        if ignored(path, args.ignore):
            continue
        text = document_text(path, size, args.staged)
        if text is not None:
            findings.extend(scan_text(normalize(path), text))

    if not findings:
        print("VERDICT: CLEAN")
        return 0

    print("")
    for line in describe(findings):
        print(line)

    # The remedy only helps for what is already committed, so ask git first.
    if not args.no_history:
        committed = [p for p in removable_paths(findings) if in_history(p)]
        if committed:
            print("")
            print("Already in history. This rewrites every commit, so read it "
                  "before you run it:")
            print("  %s" % filter_repo_command(committed))
            print("Every collaborator must re-clone afterwards.")

    return 1


if __name__ == "__main__":
    sys.exit(main())

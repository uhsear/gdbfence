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

Exit codes: 0 clean, 1 findings, 2 a git step, an install step or a flag value failed,
64 usage error.
"""

from __future__ import print_function

import argparse
import fnmatch
import io
import os
import tokenize
import re
import shutil
import subprocess
import sys
import tempfile

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
# document, and reading it to look for C:\ helps nobody.  # gdbfence: allow
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

# An absolute drive letter: C:\Users or C:/Users, escaped or not. The word  # gdbfence: allow
# boundary keeps https:// and the like out of it.
DRIVE_RE = re.compile(r"\b[A-Za-z]:[\\/]")

# An inline waiver. A line carrying this marker is skipped by the content
# rules, so a file that must carry an example path can say so. This tool's
# own self-test fixtures need it, which is the honest test of the feature.
ALLOW_RE = re.compile(r"gdbfence:\s*allow")

# A UNC share. Written \\gisfiles\parcels in a .py and \\\\gisfiles\\\\parcels  # gdbfence: allow
# once JSON has escaped it, so the pattern has to survive both spellings.
#
# The leading group is the guard: a UNC path only counts at the START of a
# path, after a quote, an equals sign or whitespace. Without it, the CIM
# spelling of a RELATIVE path, "..\\data\\parcels.gdb", contains \\data\ and  # gdbfence: allow
# every portable layer file in the repository is reported as non-portable.
UNC_RE = re.compile(r"""(?:^|[\s"'=(\[,:])(\\{2,4}[A-Za-z0-9._$-]+\\)""")

# An ArcCatalog connection folder path, written with either separator and in
# any case, because Windows resolves it that way.
#
# "Database Connections\prod.sde" carries no drive letter and no UNC host,  # gdbfence: allow
# so DRIVE_RE and UNC_RE both structurally cannot see it, and a repository full
# of these scans clean. It is not portable: ArcGIS resolves it against
# %APPDATA%\ESRI\Desktop10.x\ArcCatalog in ONE user profile. The build agent has  # gdbfence: allow
# no such folder and neither does the service account, so the job runs at the
# desk it was written at and nowhere else. Measured over a 743-file legacy
# estate: 279 files name the folder and 56 of them held a connection path that
# no other rule here reported.
CONNECTION_FOLDER_RE = re.compile(r"Database Connections[\\/]", re.I)

# A path made only of these characters needs no quoting in the printed
# filter-repo command. Anything else is double quoted. GIS paths have spaces in
# them as a matter of routine, and an unquoted --path C:/GIS Data/parcels.gdb is  # gdbfence: allow
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


def strip_python_prose(text):
    """Split Python source into (code, prose), each keeping every offset.

    A drive letter in "ws = C:/gis/staging" is the defect this tool exists to  # gdbfence: allow
    catch. The same characters inside a comment explaining that defect are
    documentation, and flagging them makes the hook noisy enough to uninstall.
    gdbfence flagged its own source this way, twice, from two of its comments.

    Two views of the same text come back, both the same shape as the input:
    "code" with the comment and docstring SPANS blanked, and "prose" with
    everything else blanked. Only the spans are replaced, with spaces, so a line
    holding both code and a trailing comment keeps its code in one view and its
    comment in the other. Blanking whole lines instead hid a real hardcoded path
    that shared a line with a comment.

    The prose view exists so the waiver can be read from the comment ALONE. Read
    from the raw line, "gdbfence: allow" written inside a string literal waived
    the real hardcoded path sitting next to it on that line.

    Text that does not parse as Python comes back as itself twice, so the raw
    fallback scan still sees a waiver written anywhere on the line.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # Not parseable as Python. Scan it raw rather than skipping it entirely.
        return text, text

    lines = text.split(chr(10))
    prev = None
    spans = []
    for kind, _text, start_pos, end_pos, _line in tokens:
        drop = False
        if kind == tokenize.COMMENT:
            drop = True
        elif kind == tokenize.STRING:
            # A docstring stands alone as a statement, so what precedes it opens
            # a logical line instead of continuing one.
            if prev in (None, tokenize.INDENT, tokenize.DEDENT,
                        tokenize.NEWLINE, tokenize.NL):
                drop = True
        if drop:
            spans.append((start_pos, end_pos))
        if kind not in (tokenize.NL, tokenize.COMMENT):
            prev = kind

    code = list(lines)
    prose = [" " * len(line) for line in lines]
    for (srow, scol), (erow, ecol) in spans:
        for row in range(srow, erow + 1):
            if row - 1 >= len(lines):
                break
            line = lines[row - 1]
            begin = scol if row == srow else 0
            finish = ecol if row == erow else len(line)
            # Blanking preserves length, so the offsets of a later span on the
            # same line are still right after an earlier one has been applied.
            code[row - 1] = (code[row - 1][:begin] + " " * (finish - begin)
                             + code[row - 1][finish:])
            prose[row - 1] = (prose[row - 1][:begin] + line[begin:finish]
                              + prose[row - 1][finish:])
    return chr(10).join(code), chr(10).join(prose)


def scan_text(path, text):
    """Findings for the CONTENT of one text or CIM document.

    Kept apart from audit() so the size and completeness rules never need a file
    to be readable, and so this one is testable against a string literal.
    """
    waiver_lines = text.splitlines()
    if path.lower().endswith((".py", ".pyt")):
        text, prose = strip_python_prose(text)
        waiver_lines = prose.splitlines()
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        # The waiver is NOT read from the line being scanned. The stripper has
        # already erased the comment carrying it by this point, so checking the
        # stripped line finds nothing and the waiver silently does not work.
        # In Python it is read from the comments and docstrings only, so that a
        # string literal holding the marker cannot waive the code beside it. In
        # anything else there is no comment syntax to trust, so the raw line is
        # the only thing there is to read.
        if line_no <= len(waiver_lines) and ALLOW_RE.search(
                waiver_lines[line_no - 1]):
            continue
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
            continue
        # Checked last, so a line that also carries a drive letter or a UNC host
        # keeps the older, more specific message.
        m = CONNECTION_FOLDER_RE.search(line)
        if m:
            findings.append(Finding(
                NON_PORTABLE_PATH, path,
                "line %d holds the ArcCatalog connection path \"%s\", which only "
                "resolves in the user profile that made the connection file"
                % (line_no, m.group(0))))
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


def hook_interpreter(executable=None):
    """The interpreter the generated hook should call.

    "python" is not a command on a stock Ubuntu, which ships python3 and no
    unversioned alias. A hook heading "exec python" therefore fails to start,
    git reports the non-zero exit as a refusal, and that refusal looks like
    gdbfence blocking the commit when nothing was ever scanned. A clean commit
    is blocked the same way. The interpreter that ran --install is the one
    interpreter known to exist, so the hook names it.
    """
    exe = executable if executable is not None else sys.executable
    return exe or "python3"


def sh_quote(text):
    """Single-quote a string for /bin/sh. An interpreter path carries spaces."""
    return "'" + text.replace("'", "'" + chr(92) + "''") + "'"


def hook_script(tool_path, executable=None):
    """The plain git pre-commit hook, as text."""
    return ("#!/bin/sh" + chr(10)
            + "# Installed by gdbfence --install. Delete this file to remove it."
            + chr(10)
            + "exec %s %s --staged" % (sh_quote(hook_interpreter(executable)),
                                       sh_quote(tool_path))
            + chr(10))


def precommit_entry(tool_path, executable=None):
    """The .pre-commit-config.yaml block, as text."""
    return ("-   repo: local" + chr(10)
            + "    hooks:" + chr(10)
            + "    -   id: gdbfence" + chr(10)
            + "        name: gdbfence" + chr(10)
            + "        entry: %s %s --staged" % (hook_interpreter(executable),
                                                 tool_path) + chr(10)
            + "        language: system" + chr(10)
            + "        pass_filenames: false" + chr(10))


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
        # Binary, so the file on disk is byte for byte the text printed above.
        # Text mode turns every newline into CRLF on Windows, and a /bin/sh
        # hook whose last line ends "--staged\r" passes a flag no argument
        # parser accepts. Git for Windows tolerates it; dash and busybox, which
        # is what the same repository meets in WSL or in a container, do not.
        with open(hook, "wb") as fh:
            fh.write(hook_script(tool_path).encode("utf-8"))
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
    """Assertions over the decision core, then over the io layer.

    Nothing here reaches the network, and nothing here touches the repository it
    is run from. The io half writes to a temporary directory and drives git
    inside it, because the hook, the read from the index and the printed
    filter-repo remedy cannot be tested any other way.
    """
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

    print("gdbfence self-test: no network, a temporary git repo for the io layer")
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
    check(normalize("./data/roads.shp") == "data/roads.shp",
          "a leading ./ is dropped, so git's spelling and the walker's agree")
    check(normalize("././data/") == "data",
          "a repeated ./ is dropped and a trailing slash with it")
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
    # The rule has two halves and each one needs its own assertion. The slice
    # is the first half: ONLY ancestors are tested, so a plain file that is
    # itself named .gdb is a file. Dropping the slice keeps the same dataset
    # key and changes only the kind, so nothing above this line goes red.
    check(dataset_of("data/parcels.gdb") == ("data/parcels.gdb", "file"),
          "a plain file named .gdb is a FILE, not a directory of 1  <-- pinned defect")
    check(audit([("data/parcels.gdb", 10)])[0].message
          == ".gdb files should never be committed",
          "so it is refused as a file, not described as a directory of files")
    # endswith is the second half. A directory whose name merely CONTAINS
    # .gdb is not a geodatabase, and a substring test would swallow everything
    # under it into one dataset named after a directory git has no such path
    # for, which is a filter-repo command that removes nothing.
    check(dataset_of("archive.gdb.backup/notes.txt")
          == ("archive.gdb.backup/notes.txt", "file"),
          "a directory whose name merely CONTAINS .gdb is not a container  <-- pinned defect")
    check(codes(audit([("archive.gdb.backup/a.bin", 50000000)])) == [BIG_DATASET],
          "so its contents are not refused as a geodatabase")

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
    # The boundary between those two messages. A file of exactly 512.0 kB is
    # what check-added-large-files ALLOWS, so this is the case the note exists
    # to describe, and a strict comparison here would drop it in silence.
    edge = audit([("data/edge.gdb/a%d.gdbtable" % i, PER_FILE_LIMIT)
                  for i in range(30)])
    edge = [x for x in edge if x.code == BIG_DATASET][0]
    check("under the 512.0 kB per-file rule" in edge.message,
          "a largest file of EXACTLY the per-file limit still passed it, so the "
          "note is still printed  <-- pinned defect")

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
    # Both sides are folded, and every assertion above this line writes the
    # PATTERN in lower case, so they hold only the path side. A person typing
    # --ignore VENDOR/* on the command line folds the other way.
    check(ignored("vendor/roads.shp", ["VENDOR/*"]),
          "an uppercase GLOB matches a lowercase path too  <-- pinned defect")
    check(codes(audit([("vendor/roads.shp", 1)], ignore=("VENDOR/*",))) == [],
          "and that direction reaches audit as well")
    # A pattern with no slash in it is matched against the basename, so
    # --ignore "*.tif" and --ignore "roads.shp" both work at any depth. The
    # full-path attempt alone misses the second one, because fnmatch has no
    # leading wildcard to get past "data/".
    check(ignored("data/gis/roads.shp", ["roads.shp"]),
          "a bare filename glob matches that file at any depth")
    check(ignored("data/gis/roads.shp", ["gis"]),
          "and a bare directory name ignores everything under it, so --ignore "
          "vendor needs no trailing glob")
    check(not ignored("data/gis/roads.shp", ["road"]),
          "a bare name is matched whole, never as a prefix of a longer one")

    # ---- things that should never be committed
    check(codes(audit([("conn.sde", 10)])) == [NEVER_COMMIT_CODE],
          "a .sde connection file is refused")
    check(codes(audit([("parcels.gdb.lock", 10)])) == [NEVER_COMMIT_CODE],
          "a .lock file is refused")
    check(codes(audit([("old/parcels.mdb", 10)])) == [NEVER_COMMIT_CODE],
          "a personal geodatabase .mdb is refused")
    check(codes(audit([("parcels.gdbindexes", 10)])) == [NEVER_COMMIT_CODE],
          "a .gdbindexes file is refused")
    check(codes(audit([("x.gdbindexes/a.bin", 10)])) == [NEVER_COMMIT_CODE],
          "and so is a .gdbindexes directory, as one dataset")
    check(codes(audit([("notes.txt", 10)])) == [],
          "an ordinary text file is not refused")

    # ---- non-portable paths in text and CIM documents
    cim = ('{"dataConnection": {"workspaceConnectionString": '
           '"DATABASE=C:\\\\GIS\\\\parcels.gdb"}}')  # gdbfence: allow
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
    check(codes(scan_text("etl.py", 'ws = r"D:/gis/staging"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "a forward slash drive letter is caught too")
    check(codes(scan_text("etl.py", 'ws = r"\\\\gisfiles\\parcels\\current"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "a UNC share path is non-portable")
    check(codes(scan_text("etl.py", '{"p": "\\\\\\\\gisfiles\\\\\\\\parcels"}'))
          == [NON_PORTABLE_PATH],
          "a UNC path survives JSON escaping")
    check(scan_text("readme.md", "see https://example.org/a") == [],
          "a URL is not a drive letter")
    check(scan_text("etl.py", 'ws = "./data/parcels.gdb"') == [],
          "a relative workspace is fine")
    check(len(scan_text("a.py", 'x = "C:/a"\ny = 1\nz = "E:/b"')) == 2,  # gdbfence: allow
          "every offending line is reported, not just the first")

    # ---- the ArcCatalog connection folder. No drive letter and no UNC host, so
    # the two rules above cannot see it, and a whole repository of these used to
    # scan clean.
    bs = chr(92)
    f = scan_text("etl.py", 'ws = "Database Connections' + bs + bs + 'prod.sde"')
    check(codes(f) == [NON_PORTABLE_PATH],
          "a per-user connection folder path is non-portable  <-- pinned defect")
    check("Database Connections" in f[0].message and "line 1" in f[0].message,
          "the report names the connection folder and the line")
    check(codes(scan_text("etl.py", 'ws = "Database Connections/prod.sde"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "the forward slash spelling is caught too")
    check(codes(scan_text("etl.py", 'ws = "database connections/prod.sde"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "windows folds the case of the folder, so the rule does too")
    check(scan_text("etl.py", 'note = "Database Connections are per user"') == [],
          "the folder NAME without a path separator is prose, not a path")
    check(scan_text("a.py", "# Database Connections" + bs + "prod.sde is per-user")
          == [],
          "a connection path inside a python comment is not flagged  <-- pinned defect")
    check(scan_text("a.py", 'ws = "Database Connections' + bs + bs
                    + 'prod.sde"  # gdbfence: allow') == [],
          "the waiver covers the connection rule like every other content rule")
    both = scan_text("etl.py", 'ws = "C:/x/Database Connections/prod.sde"')  # gdbfence: allow
    check(len(both) == 1 and "absolute path" in both[0].message,
          "a line carrying both keeps the drive letter message, and reports once")

    # ---- prose in python source is documentation, not a hardcoded path
    check(scan_text("a.py", "# look for C:" + chr(92) + " helps nobody") == [],
          "a drive letter inside a python comment is not flagged  <-- pinned defect")
    check(scan_text("a.py", '"""A docstring naming C:/Users/jdoe."""') == [],  # gdbfence: allow
          "a drive letter inside a module docstring is not flagged")
    check(codes(scan_text("a.py", 'ws = "C:/gis/staging"  # the real defect'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "a drive letter in an assignment is still flagged next to a comment")
    check(codes(scan_text("a.py", 'def f():' + chr(10) + '    """doc C:/x"""'  # gdbfence: allow
                          + chr(10) + '    p = "D:/y"')) == [NON_PORTABLE_PATH],  # gdbfence: allow
          "a function docstring is skipped while its body is still scanned")
    check(scan_text("a.py", "x = (") == [],
          "unparseable python does not raise")
    check(codes(scan_text("a.py", 'x = (' + chr(10) + 'ws = "C:/gis"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "unparseable python falls back to a raw scan")
    check(codes(scan_text("notes.md", "see C:/Users/jdoe")) == [NON_PORTABLE_PATH],  # gdbfence: allow
          "a non-python file is not prose-stripped")

    # ---- the inline waiver
    check(codes(scan_text("a.py", 'ws = "C:/gis"')) == [NON_PORTABLE_PATH],  # gdbfence: allow
          "a hardcoded workspace is flagged without a waiver")
    check(scan_text("a.py", 'ws = "C:/gis"  # gdbfence: allow') == [],  # gdbfence: allow
          "the waiver is read from the original line, not the stripped one  <-- pinned defect")
    check(scan_text("notes.md", "see C:/Users/x  gdbfence: allow") == [],  # gdbfence: allow
          "the waiver works in a non-python file too")
    check(codes(scan_text("a.py", 'a = "C:/x"' + chr(10)  # gdbfence: allow
                          + 'b = "D:/y"  # gdbfence: allow'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "the waiver applies only to its own line")
    # The waiver is a licence to hold a path, so anyone editing the file can
    # write one. It must not be reachable from data the file merely CONTAINS.
    check(codes(scan_text("a.py", 'ws = "C:/gis"; note = "gdbfence: allow"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "the marker inside a STRING does not waive the real path beside it  <-- pinned defect")
    check(codes(scan_text("a.py", 'ws = "C:/gis"  # gdbfence: allow me'))  # gdbfence: allow
          == [], "the marker in a real comment on that line still waives it")
    check(codes(scan_text("a.pyt", 'ws = "C:/gis"; n = "gdbfence: allow"'))  # gdbfence: allow
          == [NON_PORTABLE_PATH],
          "a .pyt toolbox is prose-stripped and spoof-proof the same way")
    check(codes(scan_text("a.py", 'x = (' + chr(10)
                          + 'ws = "C:/gis"; n = "gdbfence: allow"'))  # gdbfence: allow
          == [], "unparseable python has no comment syntax to trust, so the raw "
                 "line waives")
    code_view, prose_view = strip_python_prose('ws = "C:/x"  # why')  # gdbfence: allow
    check("C:/x" in code_view and "why" not in code_view,  # gdbfence: allow
          "the code view keeps the code and loses the comment")
    check("why" in prose_view and "C:/x" not in prose_view,  # gdbfence: allow
          "the prose view keeps the comment and loses the code")
    check(len(code_view) == len(prose_view) == len('ws = "C:/x"  # why'),  # gdbfence: allow
          "both views keep every offset, so line numbers still mean something")

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
    check(removable_paths(scan_text("a.lyrx", 'p = "C:/gis"')) == [],  # gdbfence: allow
          "a hard-coded drive letter is NOT offered to filter-repo, you edit the line")

    # ---- input validation
    raises(lambda: normalize(None), "a null path raises")
    raises(lambda: audit([("a.tif", -1)]), "a negative size raises")
    raises(lambda: audit([("a.tif", None)]), "a null size raises")
    raises(lambda: audit([("a.tif", 1)], max_dataset_size=-1),
           "a negative --max-dataset-size raises")
    raises(lambda: audit([("a.tif", 1)], per_file_limit=-1),
           "a negative per-file limit raises")
    raises(lambda: parse_size("ten megabytes"), "an unreadable size raises")

    # ---- rendering
    check(describe([])[-1] == "VERDICT: CLEAN", "no findings renders CLEAN")
    check(describe(audit(gdb))[-1] == "VERDICT: REFUSE",
          "findings render REFUSE last")
    check(repr(Finding(BIG_DATASET, "data/parcels.gdb", "m"))
          == "Finding(BIG_DATASET, 'data/parcels.gdb')",
          "a finding reprs as its code and its path")

    # ---- argument handling. GDBFENCE_MAX_DATASET_SIZE is taken out of the
    # environment first: it supplies the default for --max-dataset-size, so a
    # developer who exports it once used to see this self-test fail.
    os.environ["GDBFENCE_MAX_DATASET_SIZE"] = "7MB"
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
        # argparse runs type= over the default as well, so an unreadable value
        # exported once is argparse's own usage error and not a traceback out of
        # a pre-commit hook.
        os.environ["GDBFENCE_MAX_DATASET_SIZE"] = "ten megabytes"
        real_stderr, sys.stderr = sys.stderr, io.StringIO()
        exit_code = None
        try:
            try:
                _parse([])
            except SystemExit as exc:
                exit_code = exc.code
        finally:
            sys.stderr = real_stderr
        check(exit_code == 2,
              "an unreadable GDBFENCE_MAX_DATASET_SIZE exits 2, not a traceback")
    finally:
        os.environ.pop("GDBFENCE_MAX_DATASET_SIZE", None)
        if saved_env is not None:
            os.environ["GDBFENCE_MAX_DATASET_SIZE"] = saved_env
    check(os.environ.get("GDBFENCE_MAX_DATASET_SIZE") == "7MB",
          "a developer's own GDBFENCE_MAX_DATASET_SIZE is put back afterwards")
    os.environ.pop("GDBFENCE_MAX_DATASET_SIZE", None)

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
    # ---- the hook must name an interpreter that exists on the host
    check("exec 'python3' " in hook_script("t.py", executable="python3"),
          "the hook execs the interpreter it was given")
    check("exec python " not in hook_script("t.py", executable="python3"),
          "the hook never execs a bare python, absent on a stock Ubuntu  <-- pinned defect")
    check(hook_interpreter("") == "python3",
          "an empty sys.executable falls back to python3, not to python")
    check(hook_interpreter("/usr/bin/python3.12") == "/usr/bin/python3.12",
          "an explicit interpreter is used as given")
    check("'C:" + chr(92) + "Program Files" + chr(92) + "py.exe'"
          in hook_script("t.py", executable="C:" + chr(92) + "Program Files" + chr(92) + "py.exe"),
          "an interpreter path holding a space is quoted for /bin/sh")
    check(sh_quote("it's") == "'it'" + chr(92) + "''s'",
          "a single quote inside a path is escaped for /bin/sh")
    check("entry: python3 t.py --staged" in precommit_entry("t.py", executable="python3"),
          "the pre-commit entry names the same interpreter")

    check(hook_script("gdbfence.py").startswith("#!/bin/sh"),
          "the git hook is a shell script")
    check("--staged" in hook_script("gdbfence.py"),
          "the git hook runs the tool against the staged files")
    check("language: system" in precommit_entry("gdbfence.py"),
          "the pre-commit entry needs no install step")

    # ---- the harness itself. A check() that cannot record a failure would
    # report every defect below as a pass, which is the one failure no other
    # assertion here could ever see. Three deliberate failures are recorded
    # against a scratch mark and then taken back off the tally.
    quiet = sys.stdout
    sys.stdout = io.StringIO()
    mark = len(failed)
    try:
        check(False, "probe: a false condition must be recorded as a failure")
        raises(lambda: None, "probe: a call that raises nothing must fail")
        raises(lambda: [][0], "probe: the wrong exception must fail")
    finally:
        sys.stdout = quiet
    probe = failed[mark:]
    del failed[mark:]
    check(len(probe) == 3,
          "check() and raises() really do record a failure  <-- pinned defect")
    check("no error raised" in probe[1] and "wrong exception" in probe[2],
          "and say which way the call under test went wrong")

    # ---- the io layer, against a real temporary git repository.
    #
    # Everything above this line is pure. Everything below writes to a
    # temporary directory and runs git, because the parts that had never run
    # were exactly the parts that do: the hook it installs, the read from the
    # index, and the history check that prints the filter-repo remedy. A remedy
    # that has never been printed against a repository which really carries a
    # geodatabase has not been tested.
    def run(args, cwd=None):
        """A command's (returncode, combined output). Drives git and gdbfence."""
        proc = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out = proc.communicate()[0]
        return proc.returncode, out.decode("utf-8", "replace")

    def capture(fn):
        """(what fn returned, everything it printed to either stream)."""
        buf = io.StringIO()
        real_out, real_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = buf
        try:
            result = fn()
        finally:
            sys.stdout, sys.stderr = real_out, real_err
        return result, buf.getvalue()

    def write(path, data):
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "wb") as fh:
            fh.write(data)

    def read(path):
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")

    me = os.path.abspath(__file__)
    tmp = tempfile.mkdtemp(prefix="gdbfence-selftest-")
    here = os.getcwd()

    def new_repo(name):
        path = os.path.join(tmp, name)
        os.makedirs(path)
        for cmd in (["init", "-q", "."],
                    ["config", "user.email", "selftest@example.org"],
                    ["config", "user.name", "gdbfence self-test"],
                    ["config", "commit.gpgsign", "false"],
                    ["config", "core.autocrlf", "false"]):
            run(["git"] + cmd, cwd=path)
        return path

    try:
        # ---- the git wrapper
        check(git(["--version"]) is not None,
              "git is on PATH, which every assertion below this line needs")
        check(git(["cat-file", "-s", "no-such-object-9c1f"], cwd=tmp) is None,
              "a git command that fails returns None instead of raising")
        check(git(["--version"], cwd=os.path.join(tmp, "no-such-dir")) is None,
              "git refused a directory that does not exist returns None too")

        # ---- reading documents off disk
        docs = os.path.join(tmp, "docs")
        lyrx = os.path.join(docs, "layer.lyrx")
        write(lyrx, b'{"w": "DATABASE=C:/GIS/parcels.gdb"}')  # gdbfence: allow
        check(codes(scan_text("layer.lyrx",
                              document_text(lyrx, os.path.getsize(lyrx))))
              == [NON_PORTABLE_PATH],
              "a .lyrx really on disk is read and its drive letter found")

        # TEXT_READ_LIMIT. The fixture carries a drive letter on its first line,
        # so a file that WAS read cannot be mistaken for one that was skipped.
        over = os.path.join(docs, "over.json")
        payload = b'{"w": "C:/GIS/parcels.gdb"}\n'  # gdbfence: allow
        write(over, payload + b" " * (TEXT_READ_LIMIT + 1 - len(payload)))
        check(os.path.getsize(over) == TEXT_READ_LIMIT + 1,
              "the oversize fixture is one byte over TEXT_READ_LIMIT")
        check(document_text(over, os.path.getsize(over)) is None,
              "a document over TEXT_READ_LIMIT is skipped, never read")
        check(document_text(over, TEXT_READ_LIMIT) is not None,
              "the SIZE is what skipped it: the same file under the limit is read")

        check(document_text(os.path.join(docs, "a.gdbtable"), 10) is None,
              "a suffix that is not a document is never opened at all")

        # Every suffix the README claims is read, read off a real file.
        #
        # This list is written out LITERALLY rather than taken from
        # TEXT_SUFFIXES. Looping over the constant only ever tests the suffixes
        # that are already in it: deleting ".sql" from TEXT_SUFFIXES left this
        # block one assertion shorter and still green, while the README went on
        # promising that a .sql file is read. The promise is the fixture.
        promised = (".lyrx", ".mapx", ".json", ".py", ".pyt", ".yml", ".xml",
                    ".sql")
        check([e for e in promised if e not in TEXT_SUFFIXES] == [],
              "every suffix the README names is one the tool really opens")
        for ext in TEXT_SUFFIXES:
            probe = os.path.join(tmp, "suffixes", "probe" + ext)
            write(probe, b'{"w": "C:/GIS/parcels.gdb"}')  # gdbfence: allow
            check(codes(scan_text(probe,
                                  document_text(probe, os.path.getsize(probe))))
                  == [NON_PORTABLE_PATH],
                  "a %s document is read and its drive letter found" % ext)
        check(document_text(os.path.join(docs, "no-such-file.json"), 10) is None,
              "a document that cannot be opened is skipped, not fatal")

        # Binary. A .gdbtable renamed to .json, or a CIM file saved by a tool
        # that wrote UTF-16, must not end the whole audit with a traceback.
        write(os.path.join(docs, "nul.json"), b"\x00\x01\x02 C:/GIS")  # gdbfence: allow
        check(document_text(os.path.join(docs, "nul.json"), 12) is None,
              "a document holding a NUL byte is binary and is skipped")
        broken = os.path.join(docs, "broken.json")
        write(broken, b'{"w": "\xff\xfe C:/GIS/parcels.gdb"}')  # gdbfence: allow
        text = document_text(broken, os.path.getsize(broken))
        check(text is not None,
              "bytes that are not valid UTF-8 are decoded, not fatal  <-- pinned defect")
        check(codes(scan_text("broken.json", text)) == [NON_PORTABLE_PATH],
              "and the drive letter inside them is still found")

        # ---- walking paths on disk
        found = dict((normalize(p), s) for p, s in walk_entries([docs]))
        check(len(found) == 4, "walking a directory finds every file under it")
        check(found[normalize(over)] == TEXT_READ_LIMIT + 1,
              "each walked file carries its real size on disk")
        check(walk_entries([over]) == [(over, TEXT_READ_LIMIT + 1)],
              "a file argument is measured directly, not walked")

        # A file the platform lists but cannot measure. Windows strips a
        # trailing space off a path, so a file created as "trailing " through
        # the \\?\ prefix is listed by os.walk and then not found by
        # os.path.getsize. One unreadable file must not take the audit down
        # with it, and it must not be counted as a zero either.
        if os.name == "nt":
            odd_dir = os.path.join(tmp, "odd")
            odd = os.path.join(odd_dir, "trailing ")
            write("\\\\?\\" + odd, b"12345")
            check(os.listdir(odd_dir) == ["trailing "],
                  "the fixture really is a file whose name ends in a space")
            check(walk_entries([odd_dir]) == [],
                  "a walked file the platform cannot stat is skipped, not fatal")
            os.remove("\\\\?\\" + odd)

        else:
            # The POSIX equivalent of a listed-but-unmeasurable file is a dangling
            # symlink: os.walk lists it, os.path.getsize raises on it. Running the
            # same pair of assertions on both hosts keeps the assertion COUNT equal,
            # so the number the README quotes is true everywhere.
            odd_dir = os.path.join(tmp, 'odd')
            os.makedirs(odd_dir)
            odd = os.path.join(odd_dir, 'dangling')
            os.symlink(os.path.join(tmp, 'no-such-target'), odd)
            check(os.listdir(odd_dir) == ['dangling'],
                  'the fixture really is a file the walker lists')
            check(walk_entries([odd_dir]) == [],
                  'a walked file the platform cannot stat is skipped, not fatal')
            os.remove(odd)
        rc, out = capture(lambda: main([docs, "--no-history"]))
        check(rc == 1, "auditing that directory refuses it")
        check("layer.lyrx" in out and "broken.json" in out,
              "both readable documents are reported by path")
        check("over.json" not in out,
              "the document over the read limit is skipped end to end, and its "
              "drive letter never reaches the report  <-- pinned defect")

        # ---- a repository that really carries a geodatabase in its history
        repo = new_repo("repo")
        os.chdir(repo)
        gdb_dir = os.path.join(repo, "data", "parcels.gdb")
        for i in range(8):
            write(os.path.join(gdb_dir, "a%08d.gdbtable" % i), b"\x00" * 300000)
        write(os.path.join(repo, "notes.txt"), b"a clean file\n")
        run(["git", "add", "-A"], cwd=repo)
        rc, out = run(["git", "commit", "-qm", "add the geodatabase"], cwd=repo)
        check(rc == 0, "the fixture repository has a geodatabase in its history")
        check(in_history("data/parcels.gdb"),
              "the history check finds a dataset that was really committed")
        check(not in_history("data/never-committed.gdb"),
              "and does not invent one that never was")

        check([normalize(p) for p, _s in walk_entries([repo])
               if "/.git/" in normalize(p)] == [],
              "walking a repository never descends into .git")

        rc, out = capture(lambda: main(["data", "--max-dataset-size", "1MB"]))
        check(rc == 1, "a geodatabase on the command line is refused, exit 1")
        check("NEVER_COMMIT  data/parcels.gdb" in out,
              "the finding names the .gdb, not the 8 files inside it")
        check("2.4 MB" in out and "over the 1.0 MB limit" in out,
              "--max-dataset-size is read end to end and the total reported")
        check("under the 512.0 kB per-file rule" in out,
              "and the per-file rule every one of those files passed is named")
        check("git filter-repo --invert-paths --force --path data/parcels.gdb"
              in out,
              "the remedy for a dataset already in history is printed in full")
        check("re-clone" in out,
              "with the warning that every collaborator must re-clone")
        check(os.path.isdir(gdb_dir) and len(os.listdir(gdb_dir)) == 8,
              "the remedy is PRINTED, never run: the .gdb is untouched  <-- pinned defect")
        rc, log = run(["git", "log", "--oneline"], cwd=repo)
        check("add the geodatabase" in log,
              "and the history it offered to rewrite is untouched  <-- pinned defect")

        rc, out = capture(
            lambda: main(["data", "--max-dataset-size", "1MB", "--no-history"]))
        check(rc == 1 and "NEVER_COMMIT" in out,
              "--no-history still reports the finding")
        check("filter-repo" not in out,
              "--no-history skips the history check, so no remedy is printed")

        rc, out = capture(lambda: main(["data", "--max-dataset-size", "1MB",
                                        "--ignore", "data/*"]))
        check(rc == 0 and "VERDICT: CLEAN" in out,
              "--ignore GLOB drops a walked directory end to end, windows "
              "separators and all")

        # A dataset that is refused but was never committed has nothing for
        # filter-repo to take out, so the remedy must stay off the screen.
        write(os.path.join(repo, "staging", "new.gdb", "a.gdbtable"),
              b"\x00" * 10)
        rc, out = capture(lambda: main(["staging"]))
        check(rc == 1 and "NEVER_COMMIT" in out,
              "a geodatabase that was never committed is still refused")
        check("filter-repo" not in out,
              "but no history remedy is printed for a path git never saw  <-- pinned defect")

        check(capture(lambda: main([me, "--no-history"]))[0] == 0,
              "gdbfence scans its own source clean  <-- pinned defect")

        # ---- --staged reads the index, not the working tree
        staged_lyrx = os.path.join(repo, "layer.lyrx")
        dirty = b'{"w": "DATABASE=C:/GIS/parcels.gdb"}'  # gdbfence: allow
        clean = b'{"w": "DATABASE=./parcels.gdb"}'
        write(staged_lyrx, dirty)
        run(["git", "add", "layer.lyrx"], cwd=repo)
        write(staged_lyrx, clean)
        check(scan_text("layer.lyrx", read(staged_lyrx)) == [],
              "the working copy on disk is clean by the time the hook runs")
        rc, out = capture(lambda: main(["--staged", "--no-history"]))
        check(rc == 1 and "NON_PORTABLE_PATH  layer.lyrx" in out,
              "--staged reads the INDEX, so fixing the file afterwards does not "
              "get the staged drive letter past the hook  <-- pinned defect")
        sizes = dict(staged_entries())
        check(sizes.get("layer.lyrx") == len(dirty) != os.path.getsize(staged_lyrx),
              "the staged SIZE comes from the index as well, not from disk")

        # An index entry git cannot size: a gitlink whose commit this repository
        # does not have. Dropping it would drop a whole dataset out of the audit
        # in silence, so the working tree answers instead.
        run(["git", "update-index", "--add", "--cacheinfo",
             "160000,0123456789012345678901234567890123456789,sub"], cwd=repo)
        write(os.path.join(repo, "sub"), b"12345")
        check(dict(staged_entries()).get("sub") == 5,
              "an index entry git cannot size falls back to the size on disk")
        run(["git", "update-index", "--add", "--cacheinfo",
             "160000,0123456789012345678901234567890123456789,ghost"], cwd=repo)
        check("ghost" not in dict(staged_entries()),
              "an entry git cannot size with nothing on disk either is dropped, "
              "not guessed at")
        run(["git", "update-index", "--force-remove", "sub"], cwd=repo)
        run(["git", "update-index", "--force-remove", "ghost"], cwd=repo)
        os.remove(os.path.join(repo, "sub"))

        # ---- git is not there to be had
        os.chdir(tmp)
        check(staged_entries() is None,
              "staged_entries outside a repository returns None, not an empty "
              "list that would read as CLEAN  <-- pinned defect")
        rc, out = capture(lambda: main(["--staged"]))
        check(rc == 2, "--staged outside a repository exits 2, not 0")
        check("git could not list staged files" in out, "and says why")
        rc, out = capture(lambda: install("gdbfence.py", True))
        check(rc == 2, "--install outside a repository exits 2")
        check("language: system" in out,
              "and still prints the pre-commit entry, which needs no repository")

        # ---- --install
        hookrepo = new_repo("hookrepo")
        os.chdir(hookrepo)
        hook = os.path.join(hookrepo, ".git", "hooks", "pre-commit")
        rc, out = capture(lambda: main(["--install"]))
        check(rc == 0 and not os.path.exists(hook),
              "--install without --apply writes NOTHING  <-- pinned defect")
        check("Re-run with --apply" in out,
              "it names the file it would write and how to write it")
        rc, out = capture(lambda: install("gdbfence.py", True))
        check(rc == 0 and os.path.isfile(hook), "--install --apply writes the hook")
        check(read(hook) == hook_script("gdbfence.py"),
              "the hook on disk is byte for byte the text printed, with no CRLF "
              "that a /bin/sh would hand to python as a flag  <-- pinned defect")
        rc, out = capture(lambda: install("gdbfence.py", True))
        check(rc == 2 and read(hook) == hook_script("gdbfence.py"),
              "a second --apply refuses to overwrite the hook and changes nothing")
        check("Refusing to overwrite" in out, "and names the file it left alone")

        badrepo = new_repo("badrepo")
        os.chdir(badrepo)
        shutil.rmtree(os.path.join(badrepo, ".git", "hooks"))
        write(os.path.join(badrepo, ".git", "hooks"), b"not a directory\n")
        rc, out = capture(lambda: install("gdbfence.py", True))
        check(rc == 2, "a hooks path that is not a directory exits 2, not a "
                       "traceback")
        check("could not write" in out, "and names the file it could not write")

        # ---- the installed hook, against real commits
        os.chdir(hookrepo)
        shutil.copy(me, os.path.join(hookrepo, "gdbfence.py"))
        write(os.path.join(hookrepo, "data", "parcels.gdb", "a.gdbtable"),
              b"\x00" * 1000)
        run(["git", "add", "-A"], cwd=hookrepo)
        rc, out = run(["git", "commit", "-m", "stage a geodatabase"],
                      cwd=hookrepo)
        check(rc != 0, "the installed hook REFUSES a commit carrying a .gdb")
        check("NEVER_COMMIT  data/parcels.gdb" in out,
              "and the refusal is gdbfence's finding, not a broken hook  <-- pinned defect")
        rc, log = run(["git", "log", "--oneline"], cwd=hookrepo)
        check("stage a geodatabase" not in log, "so the commit does not exist")

        run(["git", "reset", "-q"], cwd=hookrepo)
        write(os.path.join(hookrepo, "notes.txt"), b"a clean file\n")
        run(["git", "add", "notes.txt"], cwd=hookrepo)
        rc, out = run(["git", "commit", "-m", "a clean commit"], cwd=hookrepo)
        check(rc == 0, "the same hook lets a clean commit through  <-- pinned defect")
        check("VERDICT: CLEAN" in out,
              "having really run and found nothing, not having been skipped")
    finally:
        os.chdir(here)
        # git writes its objects read-only, and Windows refuses to unlink a
        # read-only file, so rmtree alone leaves the whole fixture repository
        # behind. Every self-test run would leak a few megabytes of temporary
        # directory, which is a poor advertisement for a tool about disk bloat.
        for root, _dirs, names in os.walk(tmp):
            for name in names:
                target = os.path.join(root, name)
                # A dangling symlink has no target to chmod, and os.walk lists it
                # among the names. Letting that raise took the whole teardown down
                # and leaked the fixture directory.
                if os.path.islink(target) or not os.path.exists(target):
                    continue
                os.chmod(target, 0o600)
        shutil.rmtree(tmp, ignore_errors=True)
        check(not os.path.isdir(tmp),
              "the self-test leaves no temporary directory behind  <-- pinned defect")

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
                    help="run the assertions and exit. The io half needs git")
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

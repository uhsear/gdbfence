# gdbfence

Refuse the commit that puts a File Geodatabase, a shapefile missing its .prj, or a path that exists on one machine only into git. Names what already bloats the history and prints the filter-repo command.

Someone runs `git add data/`. Inside `parcels.gdb` are 340 files and the largest is 411 kB, so
pre-commit's `check-added-large-files` passes every one of them against its 500 kB per-file
default. 140 MB of unmergeable binary lands on main and the clone takes eleven minutes a year
later. Nobody notices on the day, because nothing failed.

Three commits earlier, somebody staged `roads.shp`, `roads.shx` and `roads.dbf` but not
`roads.prj`. A shapefile with no `.prj` carries no CRS at all, so every checkout of it lands
wherever the reader guesses. In ArcGIS Pro that is usually the Gulf of Mexico.

Then a nightly script moves from an analyst's desk to a scheduled server. Its first call is
`AddToolbox` on `ArcGIS\Desktop10.8\ArcToolbox\Toolboxes`, built from
`os.environ["ProgramFiles(x86)"]`, so the line carries no drive letter. The server has ArcGIS
Pro and no ArcMap. The next line is one `Append` call with a field map of 2,400 characters,
and 26 of its input paths sit on two file shares. The old scan reported one share on that line
and nothing at all on the `AddToolbox` line.

```
$ python gdbfence.py --self-test
gdbfence self-test: no network, a temporary git repo for the io layer
--------------------------------------------------------------------
PASS  a file under a .gdb belongs to that .gdb
PASS  parcels.gdb.zip is ONE FILE, never walked as a directory  <-- pinned defect
PASS  a plain file named .gdb is a FILE, not a directory of 1  <-- pinned defect
PASS  340 files under one .gdb group into ONE dataset
PASS  340 files of 411 kB is ONE 139.7 MB dataset, not 340 small files
PASS  every one of those 411 kB files passes the 500 kB per-file rule
PASS  the 139.7 MB dataset is refused while all 340 files pass check-added-large-files
...
PASS  --ignore folds case the same way on every platform  <-- pinned defect
PASS  the same CIM document with a relative path is fine  <-- pinned defect
PASS  a per-user connection folder path is non-portable  <-- pinned defect
PASS  a connection path inside a python comment is not flagged  <-- pinned defect
PASS  an install-tree toolbox built from an environment variable is non-portable  <-- pinned defect
PASS  an install-tree path inside a python comment is not flagged  <-- pinned defect
PASS  every input path in a long field map is counted, not just the first  <-- pinned defect
PASS  the second share, hidden behind the first, is named  <-- pinned defect
PASS  shares hidden behind an earlier drive letter are counted  <-- pinned defect
PASS  a field map inside a python comment is not flagged  <-- pinned defect
PASS  the marker inside a STRING does not waive the real path beside it  <-- pinned defect
PASS  a path with a space is quoted into ONE argument  <-- pinned defect
PASS  a unique prefix of --apply is refused, not read as --apply  <-- pinned defect
PASS  a path that does not exist is a usage error, not a clean pass  <-- pinned defect
PASS  check() and raises() really do record a failure  <-- pinned defect
...
PASS  a document over TEXT_READ_LIMIT is skipped, never read
PASS  bytes that are not valid UTF-8 are decoded, not fatal  <-- pinned defect
PASS  the remedy for a dataset already in history is printed in full
PASS  the remedy is PRINTED, never run: the .gdb is untouched  <-- pinned defect
PASS  and the history it offered to rewrite is untouched  <-- pinned defect
PASS  gdbfence scans its own source clean  <-- pinned defect
PASS  a script on disk with an install-tree AddToolbox is refused
PASS  and its 4,000-character field map is counted in the same run
PASS  --install without --apply writes NOTHING  <-- pinned defect
PASS  the installed hook REFUSES a commit carrying a .gdb
PASS  the same hook lets a clean commit through  <-- pinned defect
PASS  the self-test leaves no temporary directory behind  <-- pinned defect
--------------------------------------------------------------------
271 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. Nothing to install, no `arcpy`, no third-party package. It runs on ArcGIS
Pro's Python and on a plain `python3` equally.

`git` is needed for `--staged`, for `--install`, and for the read-only history check that prints
the filter-repo command. Auditing paths on disk needs no repository at all. `--self-test` needs
it too: its last seventy-nine assertions build a throwaway repository in a temporary directory, install
the hook into it, and put real commits past it.

```
git clone https://github.com/uhsear/gdbfence.git
```

## Quick start

```
python gdbfence.py --self-test
python gdbfence.py data/
```

## Usage

Audit paths on disk, or audit what git has staged.

```
python gdbfence.py data/ layers/
python gdbfence.py --staged
python gdbfence.py --staged --ignore 'vendor/*' --max-dataset-size 25MB
```

`--staged` reads the index and never the working tree, for the sizes and for the document text
alike. Staging a `.lyrx` with a drive letter in it and then fixing the file on disk does not get
past the hook, because the hook reads what git is about to commit.

Install it as a hook. Nothing is written without `--apply`.

```
python gdbfence.py --install            # prints both forms, writes nothing
python gdbfence.py --install --apply    # writes .git/hooks/pre-commit
```

`--install` also prints a `.pre-commit-config.yaml` entry, so a repository that already uses
pre-commit can run this alongside `check-added-large-files` rather than instead of it.

| Flag | Default | What it does |
|---|---|---|
| `PATHS` | none | Files or directories to audit. Directories are walked. A path that does not exist is a usage error, not a clean audit. |
| `--staged` | off | Audit git's staged file list instead of `PATHS`. |
| `--max-dataset-size` | `10MB` | Largest allowed total for ONE dataset. Env: `GDBFENCE_MAX_DATASET_SIZE` |
| `--ignore` | none | Skip paths matching this glob. Repeatable. |
| `--no-history` | off | Skip the read-only git check that prints the filter-repo command. |
| `--install` | off | Print the hook forms and write `.git/hooks/pre-commit`. |
| `--apply` | off | Write the hook file. Without it nothing is written. |
| `--self-test` | off | Run the assertions and exit. The io half needs `git` and a temporary directory. |

Exit codes: 0 clean, 1 findings, 2 a git step, an install step or a flag value failed, 64 usage
error. An unreadable `--max-dataset-size`, from the flag or from the environment variable, is
argparse's own error and exits 2.

## What it refuses

- **A dataset over the size limit.** A `.gdb` directory is one dataset whose size is the sum of
  its parts, and so is a shapefile's sidecar set. The report gives the dataset total and, when the
  largest single file is itself under the per-file limit, names the rule that file passed.
- **An incomplete shapefile.** A `.shp` staged without `.shx`, `.dbf` or `.prj`. The report names
  the missing extensions and says what a missing `.prj` costs.
- **A non-portable path** inside a text or CIM document: an absolute drive letter such as
  `C:\GIS\parcels.gdb`, a UNC path such as `\\\gisfiles\parcels`, or an ArcCatalog connection
  folder path such as `Database Connections\prod.sde`, or a toolbox inside the ArcGIS install
  tree. Inside a serialized field map it counts every input path, not just the first one on the
  line. It reads `.lyrx`, `.mapx`, `.json`, `.py`, `.pyt`, `.yml`, `.xml`, `.sql` and a few
  more, and gives the line number for each one.
- **Files that should essentially never be committed**: `.gdb`, `.sde`, `.lock`, `.mdb` and
  `.gdbindexes`.

When a refused dataset is already in a commit, it prints the exact `git filter-repo` command that
removes it, with any path that is not plainly safe double quoted so that a path with a space in it
stays one argument. It prints the command and stops. That command rewrites every hash and forces
every collaborator to re-clone, so the person who owns that decision is the person reading the
output.

Only bloat and never-commit findings are offered to filter-repo. A shapefile missing its `.prj`
is fixed by committing the `.prj`, and a hard-coded drive letter is fixed by editing the line.
Offering to rewrite history for either one is the wrong remedy aimed at a real problem.

## Why not just use check-added-large-files

Use it. It is healthy, maintained, and it catches the single 80 MB GeoTIFF that this tool also
catches. It is not competing with this one.

It is the wrong shape for GIS, and the shape is the whole problem. It measures one file at a
time, at 500 kB, and it has no concept of a directory that is one dataset. 340 files of 411 kB
are 340 passes and one 140 MB repository:

```
$ python gdbfence.py data --no-history
gdbfence: 343 file(s) from 1 path(s) on the command line

  NEVER_COMMIT  data/parcels.gdb
      a geodatabase directory (340 file(s) here) is binary and unmergeable, keep it out of git entirely
  BIG_DATASET  data/parcels.gdb
      one dataset of 340 file(s) totalling 139.7 MB, over the 10.0 MB limit, and its largest single file is 411.0 kB, under the 512.0 kB per-file rule
  INCOMPLETE_SHAPEFILE  data/roads.shp
      incomplete shapefile, missing .prj. Without .prj it carries no CRS and the reader guesses
VERDICT: REFUSE
```

It has no concept of a sidecar set either, so a shapefile missing its `.prj` is three perfectly
acceptable small files. The missing file is the defect, and a per-file check can only ever look
at files that are present.

The naive version of this tool has its own trap, and the self-test pins it. A substring test for
`.gdb` turns `archive/parcels.gdb.zip` into a directory that is never walked and a dataset that
is never reported. The rule that stops it has two halves: only ANCESTOR path components are
tested, and each is tested with `endswith` rather than for a substring. Eight assertions hold that
line and each half has its own, because a fixture that only ever names `parcels.gdb.zip` leaves
the other half free to change with nothing going red.

`Database Connections\prod.sde` is the one that hides. It carries no drive letter and
no UNC host, so the two patterns above structurally cannot see it, and a repository full of them
scans clean. ArcGIS resolves that path against `%APPDATA%\ESRI\Desktop10.x\ArcCatalog` in
one user profile. The build agent has no such folder, the service account has no such folder,
and the job runs at the desk that wrote it and nowhere else. Measured over a 743-file legacy
ArcGIS estate, 279 files name that folder, and 56 of them held a connection path that no other
rule here reported. The folder name with no path separator after it stays silent, because that
is prose about a feature and not a path.

The UNC check had the same shape of bug, found by running it. A CIM document spells a relative
path `"..\\data\\parcels.gdb"`, which contains `\\data\`, so the first pattern reported every
portable layer file in the repository as non-portable. A UNC path now only counts at the start of
a path, and two more assertions pin it.

Credential scanning is deliberately absent. `gitleaks` and `detect-secrets` do that properly, and
an `.sde` file with a saved password is caught here as an `.sde` file, not as a secret.

## Paths that exist on one machine only

Two more path shapes passed every rule above. Both run fine at the desk that wrote them.

**A toolbox in the ArcGIS install tree.** ArcMap kept its system toolboxes under
`ArcGIS\Desktop10.x\ArcToolbox\Toolboxes`. ArcGIS Pro 3.6 keeps them under
`ArcGIS\Pro\Resources\ArcToolBox\toolboxes`, which is the spelling on disk. A script that hands
either path to `AddToolbox` runs only where that release is installed. When the path is built
from `os.environ["ProgramFiles(x86)"]` or `%ProgramFiles%`, it has no drive letter, so the
drive-letter rule cannot see it. The rule matches `ArcToolbox\Toolboxes\` with either separator,
in any case and escaped or not, and the message names the release when the path gives one. Esri's
[ImportToolbox reference](https://doc.esri.com/en/arcgis-pro/latest/arcpy/functions/importtoolbox.html)
says the function "is equivalent to the AddToolbox function", and that "any of the core ArcGIS
toolboxes are accessible in a script by default". So the fix is usually to delete the line. When
the path also has a drive letter, the line is reported once, as an install path.

**Every input path inside a field map.** `FieldMappings.exportToString` and a ModelBuilder
export both write one entry per output field, in this shape. This line is copied from a real
call under ArcGIS Pro 3.6 against a synthetic feature class:

```
NAME "NAME" true true false 50 Text 0 0,First,#,<input path>,NAME,0,49
```

One `Append` call can carry hundreds of these entries in one string. The UNC rule reports the
first path on a line and stops, so the second share in that string was never named. A drive
letter early in the string hid every share after it. Now each entry whose merge rule is one that
the [FieldMap reference](https://doc.esri.com/en/arcgis-pro/latest/arcpy/classes/fieldmap.html)
lists (First, Last, Join, Min, Max, Mean, Median, Sum, StDev, Count) has its input path judged
alone. The line gets one finding that counts the paths under each root. Any path outside the
field map on that line is still judged by the ordinary rules.

Before and after, on the synthetic script from the story at the top:

```
$ python gdbfence.py scripts --no-history          # the version before this rule
gdbfence: 1 file(s) from 1 path(s) on the command line

  NON_PORTABLE_PATH  scripts/nightly_append.py
      line 5 holds the UNC path "\\filesrv01\", which only resolves inside one network
VERDICT: REFUSE

$ python gdbfence.py scripts --no-history
gdbfence: 1 file(s) from 1 path(s) on the command line

  NON_PORTABLE_PATH  scripts/nightly_append.py
      line 4 holds the ArcGIS install-tree path "ArcGIS\Desktop10.8\ArcToolbox\Toolboxes\", which exists only where that ArcGIS release is installed. The core toolboxes need no AddToolbox
  NON_PORTABLE_PATH  scripts/nightly_append.py
      line 5 holds a field map with 26 input path(s) that resolve on one network or machine only: 25 under \\filesrv01\, 1 under \\filesrv02\
VERDICT: REFUSE
```

### Why not just use Analyze Tools For Pro

Use it before a migration. Esri's
[Analyze Tools For Pro](https://pro.arcgis.com/en/pro-app/3.6/tool-reference/data-management/analyzetoolsforpro.htm)
checks scripts and toolboxes for what ArcGIS Pro does not support: unsupported tools and
environments, `arcpy.mapping`, personal geodatabases and Python 2 code. Those are its job, and
gdbfence checks none of them.

A path that exists on one machine is not on its list, because that script is valid Pro Python.
Run under ArcGIS Pro 3.6 against the same synthetic script, it reported this:

```
Analyzing Python script ...\scripts\nightly_append.py for use within ArcGISPro:
No problems
```

## Waiving a line

A file that must carry an example path says so on that line:

```python
ws = "C:/gis/staging"  # gdbfence: allow
```

The waiver applies only to the line it sits on. In Python it is read from the
comments and docstrings alone, never from the code, so a string literal that
merely contains the marker cannot waive a real hardcoded path sitting beside it
on that line. In any other file type there is no comment syntax to trust, so the
marker counts anywhere on the line. gdbfence uses the waiver on its own test
fixtures, and scans its own source clean.

In Python and .pyt files, comments and docstrings are not scanned at all. A
drive letter in prose is documentation. One in an assignment is the defect.

## Limits

- It knows a comment from code in `.py` and `.pyt` files only. In a `.md`, `.json` or `.lyrx`
  file every line is code, so a drive letter written in prose is still reported. Waive that line,
  or use `--ignore` for the file.
- Size only, not content. It has no opinion about whether 9 MB of geodatabase is worth committing,
  only that 11 MB is over the limit.
- `--ignore` is `fnmatch`, not `.gitignore` syntax. `vendor/*` and `*.tif` work. Negation and `**`
  do not. It ignores case on every platform, so `vendor/*` also skips `VENDOR/roads.shp`.
- It never runs `git filter-repo`, and it never stages, unstages or deletes anything. `--apply`
  writes one file, the pre-commit hook, and refuses to overwrite a hook that already exists.
- The hook it writes calls `python gdbfence.py --staged` from the repository root, so keep a copy
  of the file there, or edit the one line in `.git/hooks/pre-commit`. It is written with LF line
  endings on every platform, because a `/bin/sh` reading a CRLF hook passes `--staged\r` on.
- A `.gdb` big enough to matter is usually already ignored. This tool is for the repository where
  that was never set up, and for the moment somebody adds a new data directory to one where it was.
- It reads sizes and document text from the git index under `--staged`, so a file that is staged
  but not yet written to disk is measured and read correctly. Auditing `PATHS` reads the working
  tree instead, which is the right answer for that question and a different one.
- A field map is read one line at a time. When an entry is split across two source lines, the
  ordinary rules judge each half, so only the first path on each line is reported.
- An install path assembled from separate pieces, such as
  `os.path.join(root, "ArcToolbox", "Toolboxes", "x.tbx")`, has no separator inside any one
  string, so the install-tree rule does not see it.
- A shapefile whose sidecars disagree about the case of the name, `ROADS.SHP` beside `roads.prj`,
  is counted as two datasets and reported incomplete. Extensions are matched without regard to
  case; the name before the extension is not.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [fcload](https://github.com/uhsear/fcload) - what to do with the geodatabase instead of committing it
- [litswap](https://github.com/uhsear/litswap) - retarget the connection string instead of committing it

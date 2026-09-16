# gdbfence

Refuse the commit that puts a File Geodatabase, a shapefile missing its .prj, or a drive letter into git. Names what already bloats the history and prints the filter-repo command.

Someone runs `git add data/`. Inside `parcels.gdb` are 340 files and the largest is 411 kB, so
pre-commit's `check-added-large-files` passes every one of them against its 500 kB per-file
default. 140 MB of unmergeable binary lands on main and the clone takes eleven minutes a year
later. Nobody notices on the day, because nothing failed.

Three commits earlier, somebody staged `roads.shp`, `roads.shx` and `roads.dbf` but not
`roads.prj`. A shapefile with no `.prj` carries no CRS at all, so every checkout of it lands
wherever the reader guesses. In ArcGIS Pro that is usually the Gulf of Mexico.

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
PASS  the marker inside a STRING does not waive the real path beside it  <-- pinned defect
PASS  a path with a space is quoted into ONE argument  <-- pinned defect
PASS  a path that does not exist is a usage error, not a clean pass  <-- pinned defect
PASS  check() and raises() really do record a failure  <-- pinned defect
...
PASS  a document over TEXT_READ_LIMIT is skipped, never read
PASS  bytes that are not valid UTF-8 are decoded, not fatal  <-- pinned defect
PASS  the remedy for a dataset already in history is printed in full
PASS  the remedy is PRINTED, never run: the .gdb is untouched  <-- pinned defect
PASS  and the history it offered to rewrite is untouched  <-- pinned defect
PASS  gdbfence scans its own source clean  <-- pinned defect
PASS  --install without --apply writes NOTHING  <-- pinned defect
PASS  the installed hook REFUSES a commit carrying a .gdb
PASS  the same hook lets a clean commit through  <-- pinned defect
PASS  the self-test leaves no temporary directory behind  <-- pinned defect
--------------------------------------------------------------------
230 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. Nothing to install, no `arcpy`, no third-party package. It runs on ArcGIS
Pro's Python and on a plain `python3` equally.

`git` is needed for `--staged`, for `--install`, and for the read-only history check that prints
the filter-repo command. Auditing paths on disk needs no repository at all. `--self-test` needs
it too: its last seventy assertions build a throwaway repository in a temporary directory, install
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
  `C:\GIS\parcels.gdb`, or a UNC path such as `\\gisfiles\parcels`. It reads `.lyrx`, `.mapx`,
  `.json`, `.py`, `.pyt`, `.yml`, `.xml`, `.sql` and a few more, and gives the line number.
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
tested, and each is tested with `endswith` rather than for a substring. Seven assertions hold that
line and each half has its own, because a fixture that only ever names `parcels.gdb.zip` leaves
the other half free to change with nothing going red.

The UNC check had the same shape of bug, found by running it. A CIM document spells a relative
path `"..\\data\\parcels.gdb"`, which contains `\\data\`, so the first pattern reported every
portable layer file in the repository as non-portable. A UNC path now only counts at the start of
a path, and two more assertions pin it.

Credential scanning is deliberately absent. `gitleaks` and `detect-secrets` do that properly, and
an `.sde` file with a saved password is caught here as an `.sde` file, not as a secret.

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
- A shapefile whose sidecars disagree about the case of the name, `ROADS.SHP` beside `roads.prj`,
  is counted as two datasets and reported incomplete. Extensions are matched without regard to
  case; the name before the extension is not.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

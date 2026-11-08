# TRISHUL extension notes

This directory is reserved for optional, operator-supplied extension material.

TRISHUL itself ships the wordlists it needs in `config/wordlists/` and uses
them by default. Nothing in this directory is required for a scan to run.

## What belongs here

TRISHUL does not download wordlists. It never clones or calls a GitHub
repository — not at install time, not at update time, and never while a scan
is running. If you are authorised to use a larger corpus, place it on disk
yourself:

```
config/wordlists/extra/common/discovery.txt
config/wordlists/extra/params/parameters.txt
```

The two sub-directories are separate on purpose: `common/` feeds host and path
discovery, `params/` feeds query-parameter discovery. A corpus never leaks
into the wrong kind of scan.

Then run:

```bash
trishul --update
```

The updater folds every `*.txt` file in those directories into the active
`common.txt` and `params.txt` lists (de-duplicated and sorted). The merge is
local, deterministic and reversible: restore the bundled list to undo it.

## Safety

Only use additional wordlists that you are authorised to use against the
target. Large wordlists increase request volume against the target — keep the
request budget in `config/default.yaml` (`scan.ffuf_max_requests`) in mind. That
budget is enforced: the wordlists are trimmed into the scan's artifact directory
so that the fuzzing requests one scan issues stay within it.

## Nuclei templates

`trishul --update` also asks the upstream `nuclei` binary to refresh its own
template set. That is the scanner updating its signature database, not TRISHUL
calling a repository as an API. To stay completely offline, point nuclei at a
local template directory and skip the template refresh.

<div align="center">

# rpt

**A small report engine, tailored specific to penetration testing**

[![CI](https://github.com/astr4liteEx/rpt/actions/workflows/ci.yml/badge.svg)](https://github.com/astr4liteEx/rpt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/astr4liteEx/rpt/sdk.svg)](https://pkg.go.dev/github.com/astr4liteEx/rpt/sdk)
![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)
![Linux | macOS | Windows](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

[Overview](#overview) • [Install](#install) • [Quick start](#quick-start) • [Commands](#commands) • [Plugins](#plugins) • [Companion projects](#companion-projects) • [Documentation](#documentation)

</div>

## Overview

In rpt, a report is a plain folder that holds markdown findings and pages, a scope table and a small YAML config. rpt defines that format, checks it, and sends it to other programs as JSON Lines. Everything else is a **plugin**, such as importing scanner output, scoring or rendering a PDF. A plugin is a separate program, in any language, that also runs on its own.

```
acme-external/
├── rpt.yaml              format version, severity levels, sections
├── scope.csv             the agreed scope: hosts, ranges, wildcard domains
├── findings/
│   ├── F-001-reflected-xss-in-search.md
│   ├── F-003-sql-injection-in-login.md
│   └── evidence/
│       └── F-003-login.png
└── pages/                report-level prose: executive summary, methodology
    └── P-001-executive-summary.md
```

- **Plain files.** Findings are markdown with YAML frontmatter. You can edit them in any editor, diff them and review them.
- **Format checking.** `rpt validate` finds missing sections, unknown severities, findings not attributed to a scope row (or to one that isn't in `scope.csv`), missing evidence files and more. It reports each problem with its file and line.
- **Unix pipelines.** Each command prints a table in a terminal and JSON Lines in a pipe, so you can chain parsers, filters and renderers.
- **No hidden state.** rpt never runs git, keeps nothing outside the report folder, and never needs a network.

> [!NOTE]
> A report holds the findings, not the engagement. The client name, test dates and title belong to whatever manages the project, and you pass them to the renderer.

## Install

**From a release:** download `rpt_<version>_<os>_<arch>.tar.gz` (`linux` or `darwin`, `amd64` or `arm64`; a `.zip` for `windows`), check it against `SHA256SUMS`, and put `rpt` on your `PATH`. The archives are reproducible: building the tagged commit with `scripts/release.sh` gives the same bytes.

**With [gah](https://github.com/get-gah/gah):** installs the latest release to `~/.local/bin` (add `--tag=<version>` for a specific one):

```sh
gah install astr4liteEx/rpt --unattended
```

**From source** (Go 1.27):

```sh
go install github.com/astr4liteEx/rpt/cmd/rpt@latest
```

To build from a clone into `~/.local/bin` (or `$PREFIX/bin`, or a folder you pass as an argument), run:

```sh
scripts/install.sh
```

> [!IMPORTANT]
> rpt is developed and tested on Linux. The macOS and Windows builds are provided but not tested; on Windows a plugin runs as a child process rather than replacing rpt.

**Shell completion:** Tab completes commands, actions, flags, IDs with their titles or hosts, severity levels, config keys and evidence references, read fresh from the report each time; a plugin completes its own arguments. Load the script for your shell:

```sh
source <(rpt completion bash)                                  # in ~/.bashrc
rpt completion zsh > "${fpath[1]}/_rpt"                        # zsh
rpt completion fish > ~/.config/fish/completions/rpt.fish      # fish
rpt completion powershell | Out-String | Invoke-Expression     # PowerShell profile
```

In nushell, run `generate completions rpt`: nushell's own command builds a completer that calls rpt.

## Quick start

`rpt new` creates an empty report. Add scope rows with `rpt scope add`, pipe finding records into `rpt finding add`, and `rpt validate` checks the result:

![rpt new creates a report, rpt scope add adds two scope rows, rpt finding add imports three findings, each shown in a bordered table, and rpt validate reports it clean](docs/demo/quick-start.gif)

When something is wrong, `rpt validate` names the file, the line and the rule. Here a finding cites a scope row that doesn't exist; `rpt finding set` fixes that one line, and `rpt finding get` shows the finding for reading:

![rpt validate reports S-99 missing from scope.csv, pointing at the line, rpt finding set points F-002's target at S-14, rpt validate passes, and rpt finding get F-002 shows the finding between rules](docs/demo/validate.gif)

To try it yourself, starting from one blank finding and filling it in:

```sh
rpt new acme-external         # rpt.yaml, an empty scope.csv and findings/
cd acme-external

rpt scope add --host 10.0.0.5 --port 443 --protocol tcp            # row S-001
rpt finding add --title "SQL injection in login" --severity high --target S-001

rpt validate                  # F-001's Description, Remediation and Proof of concept are empty
$EDITOR findings/F-001-sql-injection-in-login.md
rpt evidence add F-001 ~/shots/login-bypass.png --link poc --text "Login bypass"   # copied in, listed, linked
rpt validate                  # clean, exits 0

rpt assemble | rpt-render-pdf --client Acme --out report.pdf
```

For a filled-in example, see [`testdata/fixture`](testdata/fixture); it contains one planted problem for `rpt validate` to find.

`rpt-render-pdf` stands for any renderer plugin. `rpt assemble` prints the whole report as one JSON record, with each finding's and page's file and every file it lists or links (its `assets`, links pointed at their absolute paths), a count of findings per severity, and the report's section headings. A renderer writes its document where `--out` says, so stdout carries only records.

## Commands

| Command | What it does |
| --- | --- |
| `rpt new <dir>` | Creates an empty report in a new or empty folder and prints its `location` record. `--like <report>` takes another report's `rpt.yaml` and `scope.csv` columns, and `--with-pages` its pages too, IDs and evidence kept, for a house setup with boilerplate methodology. |
| `rpt ls [dir]` | Lists the reports at or under a folder (default: the current one), with each one's finding count. |
| `rpt ls --current` | Prints the report every other command would act on from here, found from `--report`, `$RPT_REPORT_DIR` or the current folder. Exits 1 when there is none. |
| `rpt finding get [id...]` | Prints every finding, or those with the IDs given. `--lines` adds each finding file's absolute path and where each frontmatter key (`lines.keys`: line and column) and section sits in it, for checkers that load files or report problems by position. `--assets` adds every file the finding lists or links, so `rpt finding get --assets F-003 \| jq 'del(.id)' \| rpt finding add --report ../other` copies it to another report, evidence and all. |
| `rpt finding add` | Writes each finding record on stdin as a new finding file. With `--title` and `--severity` (and `--target`, `--id`), writes one blank finding with an empty heading for each required section. A `--target` is a scope ID (`S-14`) or a map (`'{scope: S-20, port: 22}'`). A severity that isn't one of the report's is refused. |
| `rpt finding set <id> <path> <value>...` | Changes one value, given as YAML. The path is a frontmatter key, `sections.<key>` (the text from stdin when no value is given, adding the section if it's missing) or `x-<plugin>.<key>`. Several values make a list: `targets S-12 '{scope: S-20, port: 443}'`. Setting `id` renames the finding, and its file when the name starts with the old ID. Only the lines that change are rewritten. |
| `rpt finding unset <id> <path>...` | Removes frontmatter keys, sections and plugin keys. A finding's `id`, `title` and `severity` can't be removed. |
| `rpt finding remove <id>...` | Removes findings, after asking on a terminal; elsewhere pass `--yes`. Their evidence files stay. |
| `rpt page get [id...]` | Prints the report's pages of prose, such as an executive summary. `--lines` adds where each page's parts sit in its file; `--assets` is as for findings. |
| `rpt page add` | Writes each page record on stdin as a new page file, or one empty page from `--title` (and `--id`). |
| `rpt page set <id> <path> <value>...` | Changes a page's `title`, `evidence`, `body` (from stdin when no value is given) or another key. Setting `id` rewrites `pages` and `required_pages` in `rpt.yaml` too. |
| `rpt page unset <id> <path>...` | Removes keys from a page; `body` empties it. |
| `rpt page remove <id>...` | Removes pages, after asking on a terminal; elsewhere pass `--yes`. A page `rpt.yaml` lists is refused unless you pass `--force` (leave the entry) or `--cleanup` (drop it). |
| `rpt scope get [id...]` | Prints scope rows, or only those with the IDs given. `--lines` adds the line of `scope.csv` each row starts on. |
| `rpt scope add` | Appends each scope record on stdin to `scope.csv`, or one row from `--host` (and `--port`, `--protocol`, `--id`, `--col name=value`). A row without an ID gets the next free `S-NNN`, counting the IDs findings cite as well as the rows. |
| `rpt scope set <id> <column> <value>` | Changes one cell of a row. Setting `id` renames the row and every finding target citing it. A change that leaves a citing target unfit (a new port, say) is refused unless you pass `--force` (leave it) or `--cleanup` (drop it). |
| `rpt scope unset <id> <column>...` | Blanks cells of a row. A row's `id` and `host` can't be blanked. |
| `rpt scope remove <id>...` | Removes scope rows, after asking on a terminal; elsewhere pass `--yes`. A row a finding cites is refused unless you pass `--force` (leave the targets dangling) or `--cleanup` (drop them). |
| `rpt scope match` | Reads finding records on stdin and attributes each target that has a `host` and no scope ID to the most specific scope row covering it. `--drop-out-of-scope` drops targets no row covers, and findings left with none. |
| `rpt evidence get [owner...]` | Lists every evidence file the findings and pages list or link to, with its path, media type and whether it exists; a link also gives its text, section, line and column. `--orphans` adds the files in `findings/evidence/` and `pages/evidence/` that nothing references. |
| `rpt evidence add <owner> <file>...` | Lists files in a finding's or page's evidence. A file already in the report is listed where it is; others are copied into `findings/evidence/` or `pages/evidence/` as `<id>-<name>.<ext>` (`--as <name>` names a single copy). `--link <section> --text <caption>` also links each file at the end of that section (`body` for a page), as an image when it is one. With no files, reads `evidence` records naming the owner and `file`. |
| `rpt evidence set <owner> <ref> caption\|path <value>` | `caption` rewrites the text of every link to the file, and is refused when nothing links it. `path` moves the file and rewrites every reference to it, in every finding and page. `rpt evidence unset <owner> <ref> caption` empties the caption. |
| `rpt evidence remove <owner> <ref>` | Detaches a file: its evidence list entry and image links go, and text links keep their words unless `--drop-text`. The file stays for `prune`. Asks on a terminal; elsewhere pass `--yes`. |
| `rpt evidence prune` | Removes the files in `findings/evidence/` and `pages/evidence/` that nothing references, after asking on a terminal; elsewhere pass `--yes`. `--dry-run` only lists them. |
| `rpt config get [path]` | Prints the report config as one record: severities, section headings, required sections, rule levels and plugin settings, defaults filled in. A path gives only that member; `--merged x-<plugin>` lays a plugin's report section over its user settings file. |
| `rpt config set <path> <value>...` | Changes one config value. `--rename old=new` with a new `severities` or `required_sections` list rewrites every finding using the old name; dropping a level findings still use needs `--force`. Setting `sections.<key>` (a fixed section's heading) rewrites that heading in every finding. |
| `rpt config unset <path>...` | Removes config keys; severities, sections and required sections go back to the defaults. |
| `rpt validate [id...]` | Checks the report, or only the findings, pages and scope rows named, and prints the problems. Exits 1 on any error. A problem in a finding, page or `rpt.yaml` carries the file's `rev`. |
| `rpt validate --records [id...]` | The same check, with the records it checked printed first, as the `get` commands print them with `--lines`: the config, findings, pages, scope rows and evidence, orphans included; with IDs, only those and their evidence. One read gives a tool that edits the report everything it shows, and problems that match it. |
| `rpt validate -` | Checks the records on stdin as if they were written, together, so a finding may cite a scope row from the same stream: an existing ID is a replacement, no ID is new, and a `config` record is the new `rpt.yaml`. A clean stream passes through unchanged; otherwise only problems come out (at path `-` and the record's line) and it exits 1, so `rpt validate - < new.jsonl \| rpt finding add` adds nothing when the input is broken. |
| `rpt assemble` | Prints the whole report as one JSON record for renderers. |
| `rpt completion <shell>` | Prints the completion script for `bash`, `zsh`, `fish` or `powershell`. |
| `rpt help [command]` | Lists the built-in commands, then the plugins on your `PATH`, each described the same way. A plugin a built-in hides is marked shadowed; one whose `requires` this rpt doesn't fit is hidden, and `--all` lists it marked incompatible. With a command, prints its usage, as `rpt <command> --help` does; a plugin's comes from its `--describe` summary and usage. Help about one command is text only; the list with `--json` is how tools find plugins by `roles`, `input` and `output`. |
| `rpt version` | Prints the rpt version, the record schema version and the report format version. |

**Output.** Each command prints a table in a terminal and JSON Lines in a pipe, or when you pass `--json`. In a terminal:

- A list is a bordered table in your terminal's own colours, with severities coloured and a findings table followed by a count per severity.
- `finding get` and `page get` with IDs show each one for reading: ID, title, severity, scope and path between rules, then the markdown as written, with headings coloured and prose wrapped at 80 columns. It copies cleanly. `--table` gives the table instead.
- Problems on stderr are compiler-style: `error[rule] message`, `--> path:line`, the source line with a caret under the column when known, then the totals.
- `NO_COLOR` or `TERM=dumb` drops the colour and keeps the layout. Piped output is never styled.

**Flags.** Flags are GNU-style (`--json`, not `-json`). `--report` and `--json` work on every command, before or after its name. Most commands take flags before, among or after the arguments; the `set` commands take them before the ID, because what follows the ID are values and a value may start with `-`. One of the command's own flags among those values is refused rather than written; put `--` before the ID to write it as a value.

**Picking the report.** rpt uses `--report <dir>` if you pass it, then `$RPT_REPORT_DIR`, then the nearest folder at or above the current one that holds `rpt.yaml`. To see which one that is, run `rpt ls --current`. To see which reports a folder holds, run `rpt ls`.

**Problems.** A broken file, an unknown ID or a bad input line is a `problem` record in the output, after the good records, and a line on stderr. In a terminal table you get the stderr line only. Each problem names the `command` that found it. A command that reads records stops at an error-level problem on its input: it writes nothing, passes the problems on and exits 1. Warnings never stop anything.

**Exit codes.** `0` means success. `1` means problems in the report, in its input, or in what you asked for, such as an unknown ID or a missing file, a declined confirmation, or a failure such as a write that didn't happen. `2` means a usage error, and only that: wrong flags or arguments, or `remove` without `--yes` off a terminal. `3` means a file changed while rpt was writing it, such as an editor saving at that moment, and nothing was written: run the command again. (A stale `--if-rev` is a `rev` problem, exit 1.) A plugin's own exit code passes through `rpt <plugin>`; `126` means the plugin couldn't be started.

> [!TIP]
> Every command that changes a report keeps the author's comments, quoting and line endings, and is all or nothing: it checks everything first, writes every file it touches or none, and refuses if a file changed while it worked. Use them from scripts in place of editing files by hand.

**Revs.** Finding, page, scope and config records carry a `rev`. Pass it back as `--if-rev` and the write is refused if the thing changed since you read it. `--dry-run` on any write prints what it would do, revs included, and writes nothing.

## Plugins

When a command isn't built in, `rpt <command>` runs `rpt-<command>` from your `PATH` and passes it the arguments unchanged. A `--report` given before the plugin's name reaches it as `$RPT_REPORT_DIR`. A plugin can be anything that reads and writes JSON Lines, such as a scanner importer, a CVSS scorer, a check for your house style or a PDF renderer.

![rpt help parse-scan shows the importer plugin's help, drawn from its description; its output is piped through rpt scope match, which drops an out-of-scope host, into rpt finding add](docs/demo/pipeline.gif)

```sh
set -o pipefail
rpt parse-scan < scan.csv | rpt scope match --drop-out-of-scope | rpt finding add
```

`parse-scan` is a small demo importer from [`docs/demo/setup.sh`](docs/demo/setup.sh); rpt doesn't ship it. For ready-made plugins, see [rpt-plugins](#companion-projects).

Go plugins can use the optional [`sdk`](sdk) module, which depends only on the standard library: `go get github.com/astr4liteEx/rpt/sdk@latest`. Its version matches rpt's, so `sdk/v0.2.0` goes with rpt `v0.2.0`. The plugin below adds `"source": "manual"` to every finding record and passes all other records through unchanged:

```go
package main

import (
	"fmt"
	"io"

	"github.com/astr4liteEx/rpt/sdk"
)

func main() {
	sdk.Main(sdk.Plugin{
		Description: sdk.Description{
			Summary: "Mark findings as found by hand",
			Usage:   "rpt mark-manual < findings.jsonl",
			Input:   "records", Output: "records",
		},
		Run: func(_ []string, stdin io.Reader, stdout, stderr io.Writer) int {
			code := 0
			for rec, err := range sdk.Records(stdin) {
				if err != nil {
					fmt.Fprintln(stderr, "rpt-mark-manual: stdin:", err)
					code = 1
					continue
				}
				line := rec.Raw
				if rec.Kind == "finding" {
					line, _ = sdk.SetMember(rec.Raw, "source", "manual")
				}
				stdout.Write(append(line, '\n'))
			}
			return code
		},
	})
}
```

Build it as `rpt-mark-manual` somewhere on your `PATH`, and `rpt help` will list it. The same plugin in [Rust](sdk-rust) and [Python](sdk-python) uses those SDKs, whose versions also match rpt's. They will be `rpt-sdk` on crates.io and PyPI; until they're published, depend on them from this repository. The [plugin guide](docs/plugin-guide.md) walks through building and checking a plugin in any language.

> [!WARNING]
> A shell pipeline's exit status is that of its last command. A parser that reports its failure as an error-level `problem` record stops `rpt finding add` from writing anything; one that just dies partway through can still leave a partial import, and without `set -o pipefail` the pipeline looks fine. When a partial import would cause problems, write the records to a file first: `rpt-x < in > out.jsonl && rpt finding add < out.jsonl`.

## Companion projects

rpt itself stays small: it defines the report format and checks it. Two companion projects build on it:

| Project | What it adds |
| --- | --- |
| [**rpt-tui**](https://github.com/astr4liteEx/rpt-tui) | A text user interface for working on a report without memorising the commands. |
| [**rpt-plugins**](https://github.com/astr4liteEx/rpt-plugins) | Stock plugins for common jobs, ready to put on your `PATH`. |

Both follow the [plugin protocol](docs/plugin-protocol.md), so once on your `PATH` they run through rpt: `rpt-tui` runs as `rpt tui`, and `rpt help` lists each of them.

> [!NOTE]
> rpt-tui and rpt-plugins are not published yet. They will appear under the same GitHub account, and these links will work once they do.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/report-format.md`](docs/report-format.md) | The report folder (`rpt.yaml`, `scope.csv`, finding files) and every `rpt validate` rule. |
| [`docs/plugin-protocol.md`](docs/plugin-protocol.md) | What a plugin must do: naming, `--describe`, records, output, exit codes and how it works with a report. |
| [`docs/plugin-guide.md`](docs/plugin-guide.md) | How to build a plugin step by step, the checks it should pass, and which SDK functions to use. |
| [`schema/`](schema) | JSON Schemas for each record kind: `finding`, `page`, `scope`, `config`, `evidence`, `problem`, `report`, `command`, `location` and `version`. |
| [`GLOSSARY.md`](GLOSSARY.md) | The project's terms, as the code and docs use them. |

## Development

```sh
go test ./...
scripts/check.sh   # everything CI runs: vet, staticcheck, race tests, the Rust and Python SDKs, govulncheck and a check of the release binary
scripts/release.sh --snapshot   # the release archives for every platform, from HEAD, into dist/
```

rpt and the Go SDK are two Go modules; `go.work` puts them in one workspace, so rpt builds against the SDK in `sdk/`. A release tags both on one commit, `vX.Y.Z` and `sdk/vX.Y.Z`, with `go.mod` requiring that SDK version. The Rust (`sdk-rust/`) and Python (`sdk-python/`) SDKs carry the same version in `Cargo.toml` and `pyproject.toml`; `scripts/release.sh` checks all of this. `scripts/check.sh` needs `cargo`, `python3` and [`uv`](https://docs.astral.sh/uv/) for those two. The SDKs share the conformance cases in [`testdata/sdk`](testdata/sdk).

The README's GIFs are recorded with [VHS](https://github.com/charmbracelet/vhs) from the tapes in [`docs/demo/`](docs/demo). To re-record one (`quick-start`, `validate` or `pipeline`):

```sh
docs/demo/setup.sh && vhs docs/demo/quick-start.tape
```

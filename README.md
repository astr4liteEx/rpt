<div align="center">

# rpt

**A small report engine, tailored specific to penetration testing**

[![CI](https://github.com/astr4liteEx/rpt/actions/workflows/ci.yml/badge.svg)](https://github.com/astr4liteEx/rpt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/astr4liteEx/rpt/sdk.svg)](https://pkg.go.dev/github.com/astr4liteEx/rpt/sdk)
![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)
![Linux](https://img.shields.io/badge/platform-linux-lightgrey?logo=linux&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

[Overview](#overview) • [Install](#install) • [Quick start](#quick-start) • [Commands](#commands) • [Plugins](#plugins) • [Companion projects](#companion-projects) • [Documentation](#documentation)

</div>

## Overview

In rpt, a report is a plain folder that holds markdown findings, a scope table and a small YAML config. rpt defines that format, checks it, and sends it to other programs as JSON Lines. Everything else is a **plugin**, such as importing scanner output, scoring or rendering a PDF. A plugin is a separate program, in any language, that also runs on its own.

```
acme-external/
├── rpt.yaml              format version, severity levels, sections
├── scope.csv             the agreed scope: hosts, ranges, wildcard domains
└── findings/
    ├── F-001-reflected-xss-in-search.md
    ├── F-003-sql-injection-in-login.md
    └── evidence/
        └── F-003-login.png
```

- **Plain files.** Findings are markdown with YAML frontmatter. You can edit them in any editor, diff them and review them.
- **Format checking.** `rpt validate` finds missing sections, unknown severities, scope IDs that aren't in `scope.csv`, missing evidence files and more. It reports each problem with its file and line.
- **Unix pipelines.** Each command prints a table in a terminal and JSON Lines in a pipe, so you can chain parsers, filters and renderers.
- **No hidden state.** rpt never runs git, keeps nothing outside the report folder, and never needs a network.

> [!NOTE]
> A report holds the findings, not the engagement. The client name, test dates and title belong to whatever manages the project, and you pass them to the renderer.

## Install

**From a release:** download `rpt_<version>_linux_<arch>.tar.gz` (amd64 or arm64), check it against `SHA256SUMS`, and put `rpt` on your `PATH`.

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
> rpt supports Linux only.

## Quick start

`rpt new` creates an empty report. Add scope rows to `scope.csv`, pipe finding records into `rpt add` (or write finding files by hand), and `rpt validate` checks the result:

![rpt new creates a report, two scope rows are added, rpt add imports three findings and rpt validate reports it clean](docs/demo/quick-start.gif)

When something is wrong, `rpt validate` names the file, the line and the rule. Here a finding cites a scope row that doesn't exist; `rpt set` fixes that one line, and `rpt assemble` then counts the findings per severity:

![rpt validate reports S-99 missing from scope.csv, rpt set fixes F-002's scope, and rpt validate passes](docs/demo/validate.gif)

To try it yourself, starting from one bare finding and filling it in by hand:

```sh
rpt new acme-external         # rpt.yaml, an empty scope.csv and findings/
cd acme-external

echo 'S-12,10.0.0.5,443,tcp' >> scope.csv
echo '{"kind":"finding","title":"SQL injection in login","severity":"high","scope":["S-12"]}' | rpt add

rpt validate                  # F-001 has no Description, Remediation or Proof of concept yet
$EDITOR findings/F-001-sql-injection-in-login.md
rpt validate                  # clean, exits 0

rpt assemble | rpt-render-pdf --client Acme > report.pdf
```

For a filled-in example, see [`testdata/fixture`](testdata/fixture); it contains one planted problem for `rpt validate` to find.

`rpt-render-pdf` stands for any renderer plugin. `rpt assemble` prints the whole report as one JSON record, with each finding's evidence paths made absolute and a count of findings per severity.

## Commands

| Command | What it does |
| --- | --- |
| `rpt new <dir>` | Creates an empty report in a new or empty folder. |
| `rpt ls [dir]` | Lists the reports at or under a folder (default: the current one), with each one's finding count. |
| `rpt findings [--lines]` | Lists findings. `--lines` adds each finding file's absolute path and where each frontmatter key and section sits in it, for checkers that load files or report problems by line. |
| `rpt scope` | Lists scope rows. |
| `rpt scope match` | Reads finding records on stdin and adds the IDs of the scope rows their `target` matches. `--drop-out-of-scope` drops the findings that match none. |
| `rpt severities` | Lists the report's severity levels, most severe first. |
| `rpt sections` | Lists the report's sections: the fixed ones with their headings, then the custom ones it requires. |
| `rpt add` | Reads finding records on stdin and writes each one as a new finding file. |
| `rpt set <id> <key> <value>` | Changes one frontmatter value, given as YAML. Only that line of the file changes. |
| `rpt delete <id>...` | Removes findings. Their evidence files stay. |
| `rpt validate` | Checks the report and prints its problems. Exits 1 on any error. |
| `rpt assemble` | Prints the whole report as one JSON record for renderers. |
| `rpt plugins` | Lists installed plugins. |
| `rpt verbs` | Lists the built-in verbs, described the way plugins describe themselves. |
| `rpt version` | Prints the rpt version, the record schema version and the report format version. |

**Output.** Each command prints a table in a terminal and JSON Lines in a pipe, or when you pass `--json`.

**Picking the report.** rpt uses `--report <dir>` if you pass it, then `$RPT_REPORT_DIR`, then the nearest folder at or above the current one that holds `rpt.yaml`. To see which reports a folder holds, run `rpt ls`.

**Exit codes.** `0` means success, `1` means problems in the report or its input, and `2` means a usage error.

> [!TIP]
> `rpt add`, `set` and `delete` write atomically and keep the author's comments, quoting and line endings. Use them from scripts in place of editing files by hand.

## Plugins

When a verb isn't built in, `rpt <verb>` runs `rpt-<verb>` from your `PATH` and passes it the arguments unchanged. A plugin can be anything that reads and writes JSON Lines, such as a scanner importer, a CVSS scorer, a check for your house style or a PDF renderer.

![rpt plugins lists an importer; its output is piped through rpt scope match, which drops an out-of-scope host, into rpt add](docs/demo/pipeline.gif)

```sh
set -o pipefail
rpt parse-scan < scan.csv | rpt scope match --drop-out-of-scope | rpt add
```

`parse-scan` is a small demo importer from [`docs/demo/setup.sh`](docs/demo/setup.sh); rpt doesn't ship it. For ready-made plugins, see [rpt-plugins](#companion-projects).

Go plugins can use the optional [`sdk`](sdk) package. The plugin below adds `"source": "manual"` to every finding record and passes all other records through unchanged:

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

Build it as `rpt-mark-manual` somewhere on your `PATH`, and `rpt plugins` will list it. The [plugin guide](docs/plugin-guide.md) walks through building and checking a plugin in any language.

> [!WARNING]
> A shell pipeline's exit status is that of its last command. Without `set -o pipefail`, a parser that fails partway through can still leave `rpt add` with a partial import. When a partial import would cause problems, write the records to a file first: `rpt-x < in > out.jsonl && rpt add < out.jsonl`.

## Companion projects

rpt itself stays small: it defines the report format and checks it. Two companion projects build on it:

| Project | What it adds |
| --- | --- |
| [**rpt-tui**](https://github.com/astr4liteEx/rpt-tui) | A text user interface for working on a report without memorising the commands. |
| [**rpt-plugins**](https://github.com/astr4liteEx/rpt-plugins) | Stock plugins for common jobs, ready to put on your `PATH`. |

Both follow the [plugin protocol](docs/plugin-protocol.md), so once on your `PATH` they run through rpt: `rpt-tui` runs as `rpt tui`, and `rpt plugins` lists each of them.

> [!NOTE]
> rpt-tui and rpt-plugins are not published yet. They will appear under the same GitHub account, and these links will work once they do.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/report-format.md`](docs/report-format.md) | The report folder (`rpt.yaml`, `scope.csv`, finding files) and every `rpt validate` rule. |
| [`docs/plugin-protocol.md`](docs/plugin-protocol.md) | What a plugin must do: naming, `--describe`, records, output, exit codes and how it works with a report. |
| [`docs/plugin-guide.md`](docs/plugin-guide.md) | How to build a plugin step by step, the checks it should pass, and which Go `sdk` functions to use. |
| [`schema/`](schema) | JSON Schemas for each record kind: `finding`, `scope`, `problem`, `report`, `plugin`, `severity`, `section`, `verb`, `location` and `version`. |
| [`GLOSSARY.md`](GLOSSARY.md) | The project's terms, as the code and docs use them. |

## Development

```sh
go test ./...
scripts/check.sh   # everything CI runs: vet, staticcheck, race tests, govulncheck and a check of the release binary
```

The README's GIFs are recorded with [VHS](https://github.com/charmbracelet/vhs) from the tapes in [`docs/demo/`](docs/demo). To re-record one (`quick-start`, `validate` or `pipeline`):

```sh
docs/demo/setup.sh && vhs docs/demo/quick-start.tape
```

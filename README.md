# rpt

rpt is a pentest report engine. A report is a plain folder of markdown findings, a scope table and a small config. rpt defines that format, checks it, and hands it to other programs as JSON Lines. Everything else, such as parsing scanner output, scoring and rendering a PDF, is a plugin: a separate program you can also run on its own.

rpt takes input and gives output. It never runs git, keeps no state outside the report folder, and never needs a network.

Supported system: Linux.

## Install

From a release: download `rpt_<version>_linux_<arch>.tar.gz`, check it against `SHA256SUMS`, and put `rpt` on your `PATH`.

From source (Go 1.27):

```sh
go install github.com/astr4liteEx/rpt/cmd/rpt@latest
# or, from a clone, into ~/.local/bin:
scripts/install.sh
```

## Quick start

```sh
cp -r testdata/fixture acme-external     # a report to start from
cd acme-external
rpt validate                             # check it: one problem is planted (S-99)
rpt findings                             # list findings
rpt set F-002 scope '[S-12]'             # fix the planted problem
rpt validate && rpt assemble | rpt-render-pdf --client Acme > report.pdf
```

`rpt-render-pdf` stands for any renderer plugin. The report doesn't hold the client name or test dates, so they go to the renderer.

[`docs/report-format.md`](docs/report-format.md) describes the folder: `rpt.yaml`, `scope.csv`, the finding files and every validate rule.

## Verbs

| Verb | Does |
| --- | --- |
| `rpt findings` | Lists findings. |
| `rpt scope` | Lists scope rows. |
| `rpt scope match` | Reads finding records on stdin and adds the scope IDs their `target` matches. `--drop-out-of-scope` drops the rest. |
| `rpt severities` | Lists the report's severity levels, most severe first. |
| `rpt add` | Reads finding records on stdin and writes each as a new finding file. |
| `rpt set <id> <key> <value>` | Changes one frontmatter value. The value is YAML. Only that line of the file changes. |
| `rpt delete <id>...` | Removes findings. Their evidence files stay. |
| `rpt validate` | Checks the report and prints problems. Exits 1 on any error. |
| `rpt assemble` | Prints the whole report as one JSON record for renderers. |
| `rpt plugins` | Lists installed plugins. |
| `rpt version` | Prints the rpt version, record schema version and report format version. |

Each verb prints a table on a terminal and JSON Lines into a pipe or with `--json`. `--report <dir>` picks the report; otherwise rpt uses `$RPT_REPORT_DIR`, then the nearest folder with `rpt.yaml`.

Exit codes: `0` success, `1` problems in the report or its input, `2` usage error.

## Plugins

`rpt <verb>` runs `rpt-<verb>` from your `PATH` when the verb isn't built in. A plugin can be written in any language. The rules a plugin follows are in [`docs/plugin-protocol.md`](docs/plugin-protocol.md), and the record shapes are in [`schema/`](schema). The Go [`sdk`](sdk) package implements the protocol for Go plugins.

## License

[MIT](LICENSE)

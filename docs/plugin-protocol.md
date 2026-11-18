# rpt plugin protocol

A plugin is any program, in any language, that follows this page. The core runs it as `rpt <verb>`; it also runs on its own. The record shapes live in [`schema/`](../schema); everything else a plugin must do is here. The Go [`sdk`](../sdk) package implements this protocol for Go plugins and is optional.

Supported systems: Linux.

## Finding and running a plugin

- **Name:** an executable regular file named `rpt-<verb>` in a `PATH` folder. `<verb>` is lowercase letters, digits and hyphens.
- **Lookup:** `rpt <verb>` runs the built-in verb if there is one (`rpt verbs` lists them); built-ins always win. Otherwise it runs the first `rpt-<verb>` in `PATH` order, skipping empty and relative `PATH` entries.
- **Arguments:** passed byte for byte, without the verb: `rpt parse-nuclei --strict a.json` runs `rpt-parse-nuclei --strict a.json`. rpt never parses them.
- **Process:** rpt replaces itself with the plugin (`exec`), so the plugin owns stdin, stdout, stderr, signals and the exit code. If the plugin can't be started, rpt exits 126.
- **Listing:** `rpt plugins` lists every plugin it finds, with its `--describe` answer. `rpt verbs` lists the built-ins the same way, as `verb` records.

## Environment

Set when rpt starts the plugin. A plugin runs without any of them: started directly, it falls back as shown.

| Variable | Value | Fallback when absent |
| --- | --- | --- |
| `RPT_BIN` | Absolute path of the rpt that started the plugin. Call back into rpt through it, so the plugin and the core agree on the format | `rpt` from `PATH` |
| `RPT_REPORT_DIR` | Absolute path of the report folder, found from `$RPT_REPORT_DIR` or the nearest folder holding `rpt.yaml`. Unset when there is no report | The plugin's own `--report` flag, or none |
| `RPT_SCHEMA_VERSION` | Version of the record schemas this rpt writes, now `1` | `schema_version` in the records read |

## `--describe`

Given the single argument `--describe`, print one JSON object on one line and exit 0, within 2 seconds, with no other effect:

```json
{"summary":"Parse nuclei JSON Lines into finding records","usage":"rpt parse-nuclei < results.jsonl","version":"0.3.1","input":"jsonl/nuclei","output":"records"}
```

`summary` is required; the shape is `$defs/description` in [`schema/plugin.schema.json`](../schema/plugin.schema.json). A plugin that is slower, fails or prints anything else is still listed by `rpt plugins`, with a warning and no summary.

`input` and `output` name the data the plugin takes and gives, so a person sees what it does at a glance and another plugin can find, say, the parser for Nessus XML in `rpt plugins --json`:

- `records`: an rpt JSON Lines stream (see Records).
- Anything else: `<format>` or `<format>/<tool>`, lowercase, e.g. `xml/nessus`, `jsonl/nuclei`, `pdf`. The format alone is the plain answer; the tool tells two files of one format apart. There is no registry: reuse a name another plugin already uses for the same data.
- Leave a side out when there is nothing to say; absent means "not said", not "none".

rpt never checks or acts on them. `rpt plugins` carries every member of the answer into the `plugin` record, unknown ones too, except `kind`, `name` and `path`, which are rpt's.

## Records

Data moves as **JSON Lines**: UTF-8, one JSON object per line, each with a `kind` member naming its schema: `finding`, `scope`, `problem`, `report`, `plugin`, `version`, `severity`, `section`, `verb` ([`schema/`](../schema)). Every record keeps members it doesn't know, so newer fields survive older programs.

Reading a stream:

- Accept LF or CRLF line ends; write LF.
- Skip blank lines.
- Accept lines up to 16 MiB; a longer line is a malformed line.
- A malformed line (not JSON, or JSON that isn't an object): report it on stderr with its line number (`rpt-x: stdin:12: not a JSON object`), drop it, keep reading, and exit 1 at the end.

Filtering a stream (stdin to stdout):

- **Pass through** every record you don't handle, byte for byte: other kinds, and objects with no `kind`.
- **Change only the members you own** in records you do handle, keeping the rest, unknown members included.

## Output and exit codes

- stdout carries records only: JSON Lines when stdout is a pipe or file. A table or other human form is allowed on a terminal.
- stderr carries messages, one per line: `<program>: <path>:<line>: <message>`, with `warning: ` before the message for warnings; leave out what isn't known.
- Exit codes: `0` success; `1` problems in the report or its input (the run still did what it could); `2` usage error. `126` belongs to rpt (the plugin couldn't start).

## In a pipeline

A plugin is one stage of a shell pipeline, so its failures reach the other stages:

- **A hang stalls the whole chain.** Downstream waits for input, upstream blocks once the pipe buffer fills, and nothing times out; only Ctrl-C stops it. Make every wait the plugin does (network, child processes) end on its own.
- **A crash looks like a short input.** Downstream sees end of input and finishes on the records that arrived; upstream is killed by a broken pipe. Write each record as one complete line, so a crash leaves at most one cut-off line, which readers report as malformed. On any failure, exit non-zero.
- **Shells hide mid-chain failures.** A pipeline's exit status is its last command's, so `rpt-parse | rpt-x | rpt add` exits 0 even when `rpt-x` died, and `rpt add` has added a partial set. Tell users of the plugin, in its usage or docs, to run chains with `set -o pipefail` (bash, zsh), and to stage an import through a file when a partial import would hurt: `rpt-x < in > out.jsonl && rpt add < out.jsonl`.

## Working with a report

- **Read** through rpt: `$RPT_BIN findings --json`, `$RPT_BIN scope --json`, `$RPT_BIN severities --json` (the report's levels, most severe first, as `rpt.yaml` maps them or the defaults), `$RPT_BIN sections --json` (the fixed sections with this report's headings, then the custom sections it requires; a finding's `sections` are keyed by each record's `key`), `$RPT_BIN assemble` (one `report` record, made for renderers).
- **Change** a report only through rpt: pipe `finding` records into `$RPT_BIN add` to add findings, use `$RPT_BIN set <id> <key> <value>` to change one value, and `$RPT_BIN delete <id>...` to remove findings (their evidence files stay; a freed highest ID may be given out again, since rpt keeps no history). All three write atomically and keep the author's formatting; editing report files directly is outside the protocol.
- **Check** things the core doesn't by emitting `problem` records under your own rule names; `rpt validate`'s rule names are listed in [`schema/problem.schema.json`](../schema/problem.schema.json).
- A plugin reading `report` records checks that `schema_version` is one it knows. `$RPT_BIN version --json` tells it, before reading, which record schema and report format that rpt uses.
- A report holds no engagement details: no client, title or dates. A renderer takes them from its own input (flags, environment, its own file), as in `rpt assemble | rpt-render-pdf --client Acme --period 2026-11-02..2026-11-06`.

# rpt plugin protocol

A plugin is any program, in any language, that follows this page. The core runs it as `rpt <verb>`; it also runs on its own. The record shapes live in [`schema/`](../schema); everything else a plugin must do is here. The Go [`sdk`](../sdk) package implements this protocol for Go plugins and is optional.

Supported systems: Linux and macOS.

## Finding and running a plugin

- **Name:** an executable regular file named `rpt-<verb>` in a `PATH` folder. `<verb>` is lowercase letters, digits and hyphens.
- **Lookup:** `rpt <verb>` runs the built-in verb if there is one (`rpt` with no arguments lists them); built-ins always win. Otherwise it runs the first `rpt-<verb>` in `PATH` order, skipping empty and relative `PATH` entries.
- **Arguments:** passed byte for byte, without the verb: `rpt parse-nuclei --strict a.json` runs `rpt-parse-nuclei --strict a.json`. rpt never parses them.
- **Process:** rpt replaces itself with the plugin (`exec`), so the plugin owns stdin, stdout, stderr, signals and the exit code. If the plugin can't be started, rpt exits 126.
- **Listing:** `rpt plugins` lists every plugin it finds, with its `--describe` answer.

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
{"summary":"Parse nuclei JSON Lines into finding records","usage":"rpt parse-nuclei < results.jsonl","version":"0.3.1"}
```

`summary` is required; the shape is `$defs/description` in [`schema/plugin.schema.json`](../schema/plugin.schema.json). A plugin that is slower, fails or prints anything else is still listed by `rpt plugins`, with a warning and no summary.

## Records

Data moves as **JSON Lines**: UTF-8, one JSON object per line, each with a `kind` member naming its schema: `finding`, `scope`, `problem`, `report`, `plugin` ([`schema/`](../schema)). Every record keeps members it doesn't know, so newer fields survive older programs.

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

## Working with a report

- **Read** through rpt: `$RPT_BIN findings --json`, `$RPT_BIN scope --json`, `$RPT_BIN assemble` (one `report` record, made for renderers).
- **Change** a report only through rpt: pipe `finding` records into `$RPT_BIN add` to add findings, and use `$RPT_BIN set <id> <key> <value>` to change one value. Both write atomically and keep the author's formatting; editing report files directly is outside the protocol.
- **Check** things the core doesn't by emitting `problem` records under your own rule names; `rpt validate`'s rule names are listed in [`schema/problem.schema.json`](../schema/problem.schema.json).
- A plugin reading `report` records checks that `schema_version` is one it knows.

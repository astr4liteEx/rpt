# rpt plugin protocol

A plugin is any program, in any language, that follows this page. The core runs it as `rpt <verb>`; it also runs on its own. The record shapes live in [`schema/`](../schema); everything else a plugin must do is here. The Go [`sdk`](../sdk) package implements this protocol for Go plugins and is optional. For a step-by-step walk through building one, see the [plugin guide](plugin-guide.md).

Supported systems: Linux.

## Finding and running a plugin

- **Name:** an executable regular file named `rpt-<verb>` in a `PATH` folder. `<verb>` is lowercase letters, digits and hyphens.
- **Lookup:** `rpt <verb>` runs the built-in command if there is one (`rpt help` lists them); built-ins always win. Otherwise it runs the first `rpt-<verb>` in `PATH` order, skipping empty and relative `PATH` entries.
- **Arguments:** passed byte for byte, without the verb: `rpt parse-nuclei --strict a.json` runs `rpt-parse-nuclei --strict a.json`. rpt never parses them.
- **Process:** rpt replaces itself with the plugin (`exec`), so the plugin owns stdin, stdout, stderr, signals and the exit code. If the plugin can't be started, rpt exits 126.
- **Listing:** `rpt help` lists the built-ins, then every plugin it finds with its `--describe` answer, all as `command` records with `source` `builtin` or `plugin`. A plugin named like a built-in is listed with `shadowed: true`: `rpt <verb>` never runs it. `rpt --help` also lists every plugin that isn't shadowed, under "Plugin commands".

## Environment

Set when rpt starts the plugin. A plugin runs without any of them: started directly, it falls back as shown.

| Variable | Value | Fallback when absent |
| --- | --- | --- |
| `RPT_BIN` | Absolute path of the rpt that started the plugin. Call back into rpt through it, so the plugin and the core agree on the format | `rpt` from `PATH` |
| `RPT_REPORT_DIR` | Absolute path of the report folder, found from `$RPT_REPORT_DIR` or the nearest folder holding `rpt.yaml`. Unset when there is no report, and when the plugin runs on its own: to open a finding file, use `lines.file` from `$RPT_BIN findings --json --lines` | The plugin's own `--report` flag, or none |
| `RPT_SCHEMA_VERSION` | Version of the record schemas this rpt writes, now `2` | `schema_version` in the records read |

## `--describe`

Given the single argument `--describe`, print one JSON object on one line and exit 0, within 2 seconds, with no other effect:

```json
{"summary":"Parse nuclei JSON Lines into finding records","usage":"rpt parse-nuclei < results.jsonl","version":"0.3.1","input":"jsonl/nuclei","output":"records"}
```

`summary` is required; the shape is `$defs/description` in [`schema/command.schema.json`](../schema/command.schema.json). A plugin that is slower, fails or prints anything else is still listed by `rpt help`, with a warning and no summary. Every built-in answers `--describe` the same way.

`input` and `output` name the data the plugin takes and gives, so a person sees what it does at a glance and another plugin can find, say, the parser for Nessus XML in `rpt help --json`:

- `records`: an rpt JSON Lines stream (see Records).
- Anything else: `<format>` or `<format>/<tool>`, lowercase, e.g. `xml/nessus`, `jsonl/nuclei`, `pdf`. The format alone is the plain answer; the tool tells two files of one format apart. There is no registry: reuse a name another plugin already uses for the same data.
- Leave a side out when there is nothing to say; absent means "not said", not "none".

`roles` names what the plugin is, which `input` and `output` can't say: a checker and an importer both give `records`. A tool on top of rpt reads it from `rpt help --json`, say to run every checker from one key. It is an array, since a plugin can hold several roles, and each role is a promise:

- `checker`: emits `problem` records about the report; exits 1 only when one is an error; never changes the report. `rpt validate` is one.
- `filter`: reads records on stdin and writes records on stdout, such as redaction or `rpt scope match`.
- `writer`: changes the report, only through `$RPT_BIN` write verbs.
- `renderer`: reads a report record and writes a document to a place it's given (a file or folder flag); never changes the report and writes no records to stdout.

Declare only roles whose promise the plugin keeps every run. Absent means "not said", as for `input` and `output`.

```json
{"summary":"Lint finding files with rumdl","usage":"rpt lint [file...]","output":"records","roles":["checker"]}
```

rpt never checks or acts on `input`, `output` or `roles`. `rpt help` carries every member of the answer into the plugin's `command` record, unknown ones too, except `kind`, `name`, `source`, `path` and `shadowed`, which are rpt's.

## Records

Data moves as **JSON Lines**: UTF-8, one JSON object per line, each with a `kind` member naming its schema: `finding`, `scope`, `problem`, `report`, `plugin`, `version`, `severity`, `section`, `command`, `location` ([`schema/`](../schema)). Every record keeps members it doesn't know, so newer fields survive older programs.

Reading a stream:

- Accept LF or CRLF line ends; write LF.
- Skip blank lines.
- Accept lines up to 16 MiB; a longer line is a malformed line.
- A malformed line (not JSON, or JSON that isn't an object) is a problem in the input: report it as an error-level `problem` record with `path` `-`, its `line` in the stream and rule `input`, and on stderr (`rpt-x: -:12: not a JSON object`). A filter or checker drops it, keeps reading and exits 1 at the end; a writer or renderer stops, as below.
- **An error-level `problem` record on stdin** means something upstream failed. A **writer** or **renderer** stops: it changes nothing and renders nothing, passes the problems on, and exits 1, so nothing downstream of an error acts on a partial stream. A **filter** or **checker** passes it through and carries on. Warnings never stop anything. Every rpt command that reads records stops this way.

Filtering a stream (stdin to stdout):

- **Pass through** every record you don't handle, byte for byte: other kinds, and objects with no `kind`.
- **Change only the members you own** in records you do handle, keeping the rest, unknown members included.

## Output and exit codes

- stdout carries records only: JSON Lines when stdout is a pipe or file. A table or other human form is allowed on a terminal.
- **Problems go both ways:** each one is a `problem` record on stdout, in the stream with the other records, and a text line on stderr. On a terminal showing a table, the text alone. A problem names the `command` that found it (your plugin's name, as in `rpt <name>`); never change the `command` of a problem passing through. rpt does the same: a broken finding file in `rpt findings` is a problem record (rule `readable`) after the good findings, and an unknown ID is one with rule `exists`.
- stderr carries messages, one per line: `<program>: <path>:<line>:<column>: <message>`, with `warning: ` before the message for warnings; leave out what isn't known (most messages have no column).
- Exit codes: `0` success; `1` problems in the report or its input (the run still did what it could), or a failure after the arguments were understood; `2` usage error, and only that; `3` the plugin couldn't do its work, such as a tool it needs being missing, failing or timing out, so its output says nothing about the report (say why in one stderr line). `126` belongs to rpt (the plugin couldn't start).

## In a pipeline

A plugin is one stage of a shell pipeline, so its failures reach the other stages:

- **A hang stalls the whole chain.** Downstream waits for input, upstream blocks once the pipe buffer fills, and nothing times out; only Ctrl-C stops it. Make every wait the plugin does (network, child processes) end on its own.
- **A crash looks like a short input.** Downstream sees end of input and finishes on the records that arrived; upstream is killed by a broken pipe. Write each record as one complete line, so a crash leaves at most one cut-off line, which readers report as malformed. On any failure, exit non-zero.
- **Shells hide mid-chain failures.** A pipeline's exit status is its last command's, so `rpt-parse | rpt-x | rpt finding add` exits 0 even when `rpt-x` died, and `rpt finding add` has added a partial set. Tell users of the plugin, in its usage or docs, to run chains with `set -o pipefail` (bash, zsh), and to stage an import through a file when a partial import would hurt: `rpt-x < in > out.jsonl && rpt finding add < out.jsonl`.

## Working with a report

- **Read** through rpt, never by parsing report files: `$RPT_BIN finding get --json` (add IDs for only those findings; add `--lines` for each finding file's absolute path, `lines.file`, and where each frontmatter key (`{line, column}`) and section sits in it; to load a whole finding file, open `lines.file`, never `$RPT_REPORT_DIR/<path>`, which is unset when the plugin runs on its own), `$RPT_BIN scope get --json` (add `--lines` for scope.csv's absolute path, `lines.file`, and the line each row starts on, `lines.row`; a quoted field can span lines, so never count rows yourself), `$RPT_BIN config get --json` (one `config` record: the report's `severities`, most severe first, each fixed section's heading in `sections`, `required_sections` and `rules`, with the defaults filled in; a finding's `sections` are keyed by the fixed keys and custom headings), `$RPT_BIN assemble` (one `report` record, made for renderers, with the report's severities and section headings in `report`), `$RPT_BIN ls --current --json` (the report root, as a `location` record, for files a plugin keeps in the report folder; don't search for `rpt.yaml` yourself).
- **Change** a report only through rpt; editing report files directly is outside the protocol. Every write is atomic and keeps the author's formatting:
  - Findings: pipe `finding` records into `$RPT_BIN finding add`; `$RPT_BIN finding set <id> <path> <value>...` changes one value, where the path is a frontmatter key, `sections.<key>` (the text from stdin when no value is given) or `x-<plugin>.<key>`, and several values make a list; `finding unset <id> <path>...` removes them; `$RPT_BIN finding remove --yes <id>...` removes findings (their evidence files stay; a freed highest ID may be given out again, since rpt keeps no history). Writes check form only; whether the report's rules hold is `rpt validate`'s to say.
  - **`remove` asks** when stdin and stderr are terminals; a plugin isn't one, so pass `--yes`, or it exits 2 and removes nothing.
  - Evidence: `$RPT_BIN evidence add <id> <file>...` copies files into `findings/evidence/` and lists them in the finding's evidence; `$RPT_BIN evidence --orphans` and `evidence prune` find and remove files nothing references.
  - Scope: pipe `scope` records into `$RPT_BIN scope add`; `$RPT_BIN scope set <id> <column> <value>` changes a cell (renaming an ID rewrites every citing target), `scope unset <id> <column>...` blanks cells, and `$RPT_BIN scope remove --yes <id>...` removes rows. A row a finding cites, or a change a citing target no longer fits, is refused unless `--force` (leave it dangling) or `--cleanup` (drop those targets).
  - **All or nothing.** A write checks everything first: one refused record or ID and nothing is written. A write that touches several files stages them all, reads each again, and refuses (rule `rev`, "changed since read") if any changed since it read them; it never overwrites an editor's save. Refusals are error-level `problem` records on stdout, and stderr text, exit 1: rule `exists` for an unknown ID, `rev` for a stale rev, `write` for anything else refused. In the rare case a write stops partway through its commit, each file not written is a `notWritten` problem; run the same command again to finish.
  - **Revs.** Finding, scope and evidence records carry a `rev`: opaque, compared for equality only. A plugin that computes a change from what it read passes the rev back, `--if-rev <rev>` (or `--if-rev <id>=<rev>`, repeatable, when the command names several things), and the write is refused if the thing changed since. The records a write prints carry the new revs.
  - **`--dry-run`** on every write checks it and prints exactly what the write would, revs included, and writes nothing.
- **Check** things the core doesn't by emitting `problem` records under your own rule names; `rpt validate`'s rule names are listed in [`schema/problem.schema.json`](../schema/problem.schema.json). To point at a line, take it from `$RPT_BIN findings --json --lines` or, for a scope row, `$RPT_BIN scope --json --lines`. In a finding, line `text + n` of a section is line n+1 of that section's text. A `column` (1-based byte in the line) may follow the line.
- **Ask, don't re-derive.** rpt is the only parser of report files. A stock plugin (shipped in rpt-plugins) or a community plugin never parses finding files, `rpt.yaml` or `scope.csv` itself. Loading a finding file whole and read-only, at the path rpt gives (for example to lint it or scan it for secrets, or to hand it unchanged to a tool that does), is not parsing it; working out its frontmatter or sections yourself is, so take those from `findings --json --lines`. When it needs something rpt doesn't give and every plugin would want it, that is a feature request for rpt, not code in the plugin. A local plugin, one you keep for yourself, may do whatever works for you.
- A plugin reading `report` records checks that `schema_version` is one it knows. `$RPT_BIN version --json` tells it, before reading, which record schema and report format that rpt uses.
- A report holds no engagement details: no client, title or dates. A renderer takes them from its own input (flags, environment, its own file), as in `rpt assemble | rpt-render-pdf --client Acme --period 2026-11-02..2026-11-06 --out report.pdf`. The report record does carry the report's section headings, `report.sections`, so a renderer needs nothing but stdin.

## Settings

A plugin keeps its settings in the report config under its own key, `x-<plugin>` (`x-lint:`, `x-spag:`, and so on). rpt keeps and edits these sections but never reads them, never warns about them, and never copies them into the assembled report. A plugin reads only its own section, so plugins never clash.

- **Per report:** the `x-<plugin>` section of `rpt.yaml`, set with `$RPT_BIN config set x-<plugin>.<key> <value>` (or the whole section, `config set x-<plugin> '{...}'`) and removed with `config unset`.
- **Per user:** `$XDG_CONFIG_HOME/rpt/plugins/<plugin>/config.yaml` (default `~/.config/rpt/plugins/<plugin>/config.yaml`), holding the same keys as the report section. Files the plugin needs beside it, such as word lists, live in the same folder.
- **Read them merged:** `$RPT_BIN config get --merged x-<plugin>` gives one `config` record whose `x-<plugin>` member is the user file with the report's section laid over it: maps merge key by key, lists and plain values are replaced. With no report in reach it is the user file alone; with neither, `{}`.
- **Precedence:** the plugin's built-in defaults, then the user file, then the report section, then flags. Decode the merged section over your defaults, then parse flags.

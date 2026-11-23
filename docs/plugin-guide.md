# Building an rpt plugin

Steps for building or changing an rpt plugin, in any language. The rules a plugin follows are in [`docs/plugin-protocol.md`](plugin-protocol.md); read it first and keep it open, since every step below applies it. Record shapes are in [`schema/`](../schema).

## 1. Place the plugin

Decide what the plugin is, since that decides which protocol sections bind it:

- **Source**: produces records from outside input (a scanner parser). Writes `finding` records; never needs stdin from rpt. It doesn't know the report's scope, so each target gets a `host` (and `port`, `protocol`) and no `scope`; `rpt scope match` attributes them.
- **Filter**: reads records on stdin, writes records on stdout (scoring, redaction). Pass-through rules apply.
- **Sink**: consumes records (a renderer reading `$RPT_BIN assemble`). Checks `schema_version`. Records key sections by fixed key (`remediation`), not heading; a renderer printing headings takes this report's from the report record's `sections`, so it needs only stdin, after a redaction filter too.
- **Checker**: emits `problem` records under its own rule names, each with `command` set to its own name, located with `$RPT_BIN finding get --json --lines`, which also gives each finding file's absolute path (`lines.file`) for loading the whole file.

Done when the plugin has a command name that is not an rpt built-in (`rpt help --json | jq -r 'select(.source=="builtin").name'` lists them) and a one-line summary.

## 2. Write `--describe`

Print the description object and exit 0, before any other work. Declare `input` and `output` (`records`, or a data type like `xml/nessus`; see the protocol's `--describe` section), reusing names other plugins already use for the same data (`rpt help --json | jq -r '.input, .output'`). Declare `roles` too, so tools find the plugin by what it is: `checker` or `filter` if step 1 placed it there, and `writer` if it changes the report; declare only roles whose promise (the same section) it keeps every run. If the plugin writes `x-<command>-…` keys, columns or record kinds, or reads settings from `x-<command>` in `rpt.yaml`, declare a schema for each under `schemas` (the protocol's `schemas` section), so `rpt validate` checks them. Declare `requires` with the schema versions and report formats it handles. Done when `rpt-<command> --describe | jq -e .summary` prints the summary and exits 0.

## 3. Write the work

Read and write records as the protocol's Records section says; reach the report only through `$RPT_BIN` (falling back to `rpt`). Done when every record kind the plugin reads or writes has been checked against its schema, member by member. If the plugin has settings, read them as the protocol's Settings section says: read them merged with `$RPT_BIN config get --merged x-<plugin>`, over the plugin's defaults, then parse flags.

## 4. Prove it

Run every check; the plugin is done when all pass:

- [ ] `--describe` answers within 2 seconds, with no other effect.
- [ ] A malformed input line gives one stderr line with its line number and exit 1, and the other records still come out.
- [ ] A record of a kind the plugin doesn't handle comes out byte-identical (filters).
- [ ] An unknown member on a record the plugin changes survives (filters).
- [ ] The plugin works with no `RPT_*` variable set.
- [ ] Findings it writes go into a scratch copy of a report with `rpt finding add`, and `rpt validate` on that copy reports no new errors (sources).
- [ ] With the plugin on `PATH`, `rpt help` lists it with `source` `plugin`, its summary, IO and roles, not shadowed, and `rpt <command>` runs it.
- [ ] It reads the report only through rpt: no parsing of finding files, `rpt.yaml` or `scope.csv` (stock and community plugins). Loading a whole finding file read-only at the path rpt gives, to lint or scan it, is allowed. If it can't do its job without that, stop and file a feature request for rpt instead (the protocol's "Ask, don't re-derive").

## Go plugins

The [`sdk`](../sdk) module (`go get github.com/astr4liteEx/rpt/sdk@latest`, standard library only) implements the protocol; use it instead of re-deriving the rules:

| Need | Use |
| --- | --- |
| `main` | `func main() { sdk.Main(plugin) }`, with `plugin` an `sdk.Plugin{Description, Run, Complete}` |
| `--describe`, `--help`, `__complete` | Answered by `sdk.Run` without calling `Run`; `Complete(args, word)` gives completion candidates (`value` or `value\tdescription`), and without it the shell completes file names |
| Tests | `sdk.Run(plugin, args, stdin, stdout, stderr)`, in-process |
| Reading a stream | `sdk.Records(stdin)`: yields each record's `Kind`, original bytes and line number, and a `*sdk.LineError` per malformed line. A writer or renderer passes `sdk.StopAtError()`: the first error-level problem comes with `sdk.ErrStopped`, to pass on before exiting 1 |
| Writing a record | `sdk.Emit(stdout, v)`: one deterministic JSON line |
| Typed records | `sdk.Finding`, `sdk.Page`, `sdk.ScopeRow`, `sdk.Config`, `sdk.Evidence`, `sdk.Problem`, `sdk.Report` (its findings and pages are `Finding` and `Page`, with `Assets`; each `Target` has its scope `Row`; `Section` is a heading), `sdk.Lines` (one shape for every `--lines`), `sdk.Command` (a `Description` with a name), `sdk.Location`, `sdk.VersionInfo`; every record type has `RecordKind()` and the `Kind…` constants name them, so `sdk.Emit` fills an empty `kind`; unknown members ride in `Extra` |
| Changing one member | `sdk.SetMember(raw, name, value)`: the other members keep their bytes |
| Settings | `sdk.Settings("<command>", &settings)` over the defaults already in `settings`, then parse flags |
| Calling rpt | `sdk.Call(ctx, stdin, "finding", "get")`: the records, exit code and stderr; `Problems()` and `Stale()` (a write refused with rule `rev`: read again). A program that starts rpt itself uses `sdk.Caller{Bin, Dir, Env, ProcessGroup}.Call`; `ProcessGroup` kills what rpt started when `ctx` is done, and isn't for plugins, since Ctrl-C no longer reaches that rpt |

Cleanup goes in `Plugin.Run`: `sdk.Main` exits when `Run` returns.

## Rust and Python plugins

The [Rust](../sdk-rust) crate and the [Python](../sdk-python) package (both `rpt-sdk`) give the same helpers under each language's names: `main` and `run` for the entry point, `records` for reading a stream, `emit`, `set_member`, typed records, `settings`, and a call into rpt (`Call` in Rust, `call` in Python), with the binary, folder, environment and process group a program that starts rpt itself chooses. Each README has the table for its language. The Python package uses only the standard library; the Rust crate needs only `serde`, `serde_json` and, on Unix, `libc`.

All three SDKs run the shared conformance cases in [`testdata/sdk`](../testdata/sdk), so they read and write records the same way. An SDK for another language should run them too.

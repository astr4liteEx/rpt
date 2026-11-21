# Building an rpt plugin

Steps for building or changing an rpt plugin, in any language. The rules a plugin follows are in [`docs/plugin-protocol.md`](plugin-protocol.md); read it first and keep it open, since every step below applies it. Record shapes are in [`schema/`](../schema).

## 1. Place the plugin

Decide what the plugin is, since that decides which protocol sections bind it:

- **Source**: produces records from outside input (a scanner parser). Writes `finding` records; never needs stdin from rpt. It doesn't know the report's scope, so each target gets a `host` (and `port`, `protocol`) and no `scope`; `rpt scope match` attributes them.
- **Filter**: reads records on stdin, writes records on stdout (scoring, redaction). Pass-through rules apply.
- **Sink**: consumes records (a renderer reading `$RPT_BIN assemble`). Checks `schema_version`. Records key sections by fixed key (`remediation`), not heading; a renderer printing headings takes this report's from the report record's `report.sections`, so it needs only stdin, after a redaction filter too.
- **Checker**: emits `problem` records under its own rule names, located with `$RPT_BIN findings --json --lines`, which also gives each finding file's absolute path (`lines.file`) for loading the whole file.

Done when the plugin has a verb name that is not an rpt built-in (`rpt help --json | jq -r 'select(.source=="builtin").name'` lists them) and a one-line summary.

## 2. Write `--describe`

Print the description object and exit 0, before any other work. Declare `input` and `output` (`records`, or a data type like `xml/nessus`; see the protocol's `--describe` section), reusing names other plugins already use for the same data (`rpt help --json | jq -r '.input, .output'`). Declare `roles` too, so tools find the plugin by what it is: `checker` or `filter` if step 1 placed it there, and `writer` if it changes the report; declare only roles whose promise (the same section) it keeps every run. Done when `rpt-<verb> --describe | jq -e .summary` prints the summary and exits 0.

## 3. Write the work

Read and write records as the protocol's Records section says; reach the report only through `$RPT_BIN` (falling back to `rpt`). Done when every record kind the plugin reads or writes has been checked against its schema, member by member. If the plugin has settings, read them as the protocol's Settings section says: the user's `config.yaml`, then its own section of the report's `.rpt-plugins.yaml`, then flags.

## 4. Prove it

Run every check; the plugin is done when all pass:

- [ ] `--describe` answers within 2 seconds, with no other effect.
- [ ] A malformed input line gives one stderr line with its line number and exit 1, and the other records still come out.
- [ ] A record of a kind the plugin doesn't handle comes out byte-identical (filters).
- [ ] An unknown member on a record the plugin changes survives (filters).
- [ ] The plugin works with no `RPT_*` variable set.
- [ ] Findings it writes go into a scratch copy of a report with `rpt findings add`, and `rpt validate` on that copy reports no new errors (sources).
- [ ] With the plugin on `PATH`, `rpt help` lists it with `source` `plugin`, its summary, IO and roles, not shadowed, and `rpt <verb>` runs it.
- [ ] It reads the report only through rpt: no parsing of finding files, `rpt.yaml` or `scope.csv` (stock and community plugins). Loading a whole finding file read-only at the path rpt gives, to lint or scan it, is allowed. If it can't do its job without that, stop and file a feature request for rpt instead (the protocol's "Ask, don't re-derive").

## Go plugins

The [`sdk`](../sdk) package implements the protocol; use it instead of re-deriving the rules:

| Need | Use |
| --- | --- |
| `main` | `func main() { sdk.Main(plugin) }`, with `plugin` an `sdk.Plugin{Description, Run}` |
| Tests, `--describe` included | `sdk.Run(plugin, args, stdin, stdout, stderr)`, in-process |
| Reading a stream | `sdk.Records(stdin)`: yields each record's `Kind`, original bytes and line number, and a `*sdk.LineError` per malformed line |
| Typed records | `sdk.Finding`, `sdk.ScopeRow`, `sdk.Problem`, `sdk.Report`, `sdk.Target`, `sdk.ReportTarget`, `sdk.ReportSection`, `sdk.SeverityLevel`, `sdk.Section`, `sdk.Verb`, `sdk.Location`; unknown members ride in `Extra` |
| Changing one member | `sdk.SetMember(raw, name, value)`: the other members keep their bytes |
| Calling rpt | `exec.Command(sdk.Bin(), "findings", "--json")` |

Cleanup goes in `Plugin.Run`: `sdk.Main` exits when `Run` returns.

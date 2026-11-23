# rpt-sdk for Python

The Python implementation of the [rpt plugin protocol](https://github.com/astr4liteEx/rpt/blob/main/docs/plugin-protocol.md). It's optional: a plugin is any program that follows the protocol. The package uses only the standard library and needs Python 3.10 or later.

```sh
pip install rpt-sdk   # once published; until then:
pip install 'rpt-sdk @ git+https://github.com/astr4liteEx/rpt#subdirectory=sdk-python'
```

The plugin below adds `"source": "manual"` to every finding record and passes all other records through unchanged ([`examples/rpt-manual`](examples/rpt-manual)):

```python
#!/usr/bin/env python3
import rpt_sdk as sdk


def work(args, stdin, stdout, stderr):
    code = 0
    for item in sdk.records(stdin):
        if isinstance(item, sdk.LineError):
            print(f"rpt-manual: -:{item.line}: {item.reason}", file=stderr)
            code = 1
            continue
        raw = item.raw
        if item.kind == sdk.KIND_FINDING:
            raw = sdk.set_member(raw, "source", "manual")
        stdout.write(raw + b"\n")
    return code


sdk.main(sdk.Plugin(
    sdk.Description(summary="Mark findings as entered by hand", usage="rpt manual < findings.jsonl",
                    input="records", output="records", roles=[sdk.ROLE_FILTER]),
    work,
))
```

Save it as `rpt-manual`, executable, somewhere on your `PATH`, and `rpt help` will list it.

| Need | Use |
| --- | --- |
| `main` | `sdk.main(sdk.Plugin(description, run, complete))` |
| `--describe`, `--help`, `__complete` | Answered by `sdk.run` without calling `run`; `complete(args, word)` gives completion candidates (`value` or `value\tdescription`), and without it the shell completes file names |
| Tests | `sdk.run(plugin, args, stdin, stdout, stderr)`, in-process, with `io.BytesIO` for stdin and stdout and `io.StringIO` for stderr |
| Reading a stream | `sdk.records(stdin)`: yields a `Rec` (`kind`, original `raw` bytes, `line`) per record and a `LineError` per malformed line. A writer or renderer passes `stop_at_error=True`: the first error-level problem raises `sdk.Stopped`, whose `rec` to pass on before exiting 1 |
| Writing a record | `sdk.emit(stdout, record)`: one JSON line, from a record type or a `dict` |
| Typed records | `Finding`, `Page`, `ScopeRow`, `Config`, `Evidence`, `Problem`, `Report`, `Location`, `Command`, `Version`, `Description` and their parts, as dataclasses with `from_json(raw)`, `from_dict(d)` and `to_dict()`; unknown members ride in `extra`, and an empty `kind` is written as the type's own |
| Changing one member | `sdk.set_member(raw, name, value)`: the other members keep their bytes |
| Settings | `sdk.settings("<command>", defaults)`: a `dict`, the merged settings over `defaults`; then parse flags |
| Calling rpt | `sdk.call("finding", "get", stdin=..., timeout=...)`: a `Result` with the records, exit code and stderr; `problems()` and `stale()` (a write refused with rule `rev`: read again) |

The package's version is rpt's: `rpt-sdk` 0.2.0 goes with rpt v0.2.0. Its tests run the shared conformance cases in the rpt repository's [`testdata/sdk`](https://github.com/astr4liteEx/rpt/tree/main/testdata/sdk), as the Go and Rust SDKs do.

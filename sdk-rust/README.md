# rpt-sdk for Rust

The Rust implementation of the [rpt plugin protocol](https://github.com/astr4liteEx/rpt/blob/main/docs/plugin-protocol.md). It's optional: a plugin is any program that follows the protocol. The crate depends only on `serde`, `serde_json` and, on Unix, `libc`.

```sh
cargo add rpt-sdk
```

The plugin below adds `"source": "manual"` to every finding record and passes all other records through unchanged ([`examples/manual.rs`](examples/manual.rs)):

```rust
use rpt_sdk::{Description, Plugin, ReadError, records, role, set_member};

fn main() {
    rpt_sdk::main(Plugin::new(
        Description {
            summary: "Mark findings as entered by hand".into(),
            usage: "rpt manual < findings.jsonl".into(),
            input: "records".into(),
            output: "records".into(),
            roles: vec![role::FILTER.into()],
            ..Default::default()
        },
        |_args, stdin, stdout, stderr| {
            let mut code = 0;
            for item in records(stdin) {
                let rec = match item {
                    Ok(rec) => rec,
                    Err(ReadError::Line(e)) => {
                        let _ = writeln!(stderr, "rpt-manual: -:{}: {}", e.line, e.reason);
                        code = 1;
                        continue;
                    }
                    Err(e) => {
                        let _ = writeln!(stderr, "rpt-manual: {e}");
                        return 1;
                    }
                };
                let mut line = rec.raw;
                if rec.kind == "finding" {
                    line = set_member(&line, "source", "manual").expect("a record is an object");
                }
                if writeln!(stdout, "{line}").is_err() {
                    return 1;
                }
            }
            code
        },
    ))
}
```

Build it as `rpt-manual` somewhere on your `PATH`, and `rpt help` will list it.

| Need | Use |
| --- | --- |
| `main` | `rpt_sdk::main(Plugin::new(description, run))`, adding `.complete(...)` for completion |
| `--describe`, `--help`, `__complete` | Answered by `rpt_sdk::run` without calling `run`; `complete(args, word)` gives completion candidates (`value` or `value\tdescription`), and without it the shell completes file names |
| Tests | `rpt_sdk::run(&plugin, &args, &mut stdin, &mut stdout, &mut stderr)`, in-process, with byte slices and `Vec<u8>` for the streams |
| Reading a stream | `records(stdin)`: yields each `Rec` (`kind`, original `raw` text, `line`), and `Err(ReadError::Line)` per malformed line. A writer or renderer calls `.stop_at_error()`: the first error-level problem comes as `Err(ReadError::Stopped(rec))`, to pass on before exiting 1 |
| Writing a record | `emit(stdout, &record)`: one JSON line, from any `Serialize` |
| Typed records | `Finding`, `Page`, `ScopeRow`, `Config`, `Evidence`, `Problem`, `Report`, `Location`, `Command`, `Version`, `Description` and their parts, all `Default` and serde types; unknown members ride in `extra`, and an empty `kind` is written as the type's own, so `Problem { .., ..Default::default() }` is a whole record |
| Changing one member | `set_member(&raw, name, &value)`: the other members keep their bytes |
| Settings | `settings("<command>", defaults)`: the merged settings over `defaults`, any `Serialize + DeserializeOwned` type; then parse flags |
| Calling rpt | `Call::new(["finding", "get"]).stdin(..).timeout(..).run()`: an `Output` with the records, exit code and stderr; `problems()` and `stale()` (a write refused with rule `rev`: read again) |
| Running rpt from a program | `.bin(..)`, `.current_dir(..)`, `.env(..)`, `.env_remove(..)` say how to start it; `.process_group()` makes the timeout kill what rpt started too. Not for plugins: Ctrl-C no longer reaches that rpt |

The crate's version is rpt's: `rpt-sdk` 0.2.0 goes with rpt v0.2.0. Its tests run the shared conformance cases in the rpt repository's [`testdata/sdk`](https://github.com/astr4liteEx/rpt/tree/main/testdata/sdk), as the Go and Python SDKs do.

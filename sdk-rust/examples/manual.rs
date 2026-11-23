//! `rpt-manual`: adds `"source": "manual"` to every finding record and passes all other
//! records through unchanged. Build it with `cargo build --example manual` and put it on
//! `PATH` as `rpt-manual`.

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
                        // A malformed line: report it, drop it, read on, exit 1 at the end.
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

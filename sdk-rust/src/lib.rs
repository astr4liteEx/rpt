//! The Rust implementation of the rpt plugin protocol: the record wire types, the [`records`]
//! stream reader, [`set_member`], and the plugin entry points [`run`], [`main`] and [`bin`].
//! Plugins in other languages follow the protocol directly; this crate is a convenience, never
//! a requirement.
//!
//! The protocol: <https://github.com/astr4liteEx/rpt/blob/main/docs/plugin-protocol.md>
//!
//! A filter that tags every finding and passes everything else through byte for byte:
//!
//! ```no_run
//! use rpt_sdk::{Description, Plugin, ReadError, records, set_member};
//!
//! fn main() {
//!     rpt_sdk::main(Plugin::new(
//!         Description {
//!             summary: "Mark findings as entered by hand".into(),
//!             usage: "rpt manual < findings.jsonl".into(),
//!             input: "records".into(),
//!             output: "records".into(),
//!             roles: vec![rpt_sdk::role::FILTER.into()],
//!             ..Default::default()
//!         },
//!         |_args, stdin, stdout, stderr| {
//!             let mut code = 0;
//!             for item in records(stdin) {
//!                 let rec = match item {
//!                     Ok(rec) => rec,
//!                     Err(ReadError::Line(e)) => {
//!                         let _ = writeln!(stderr, "rpt-manual: -:{}: {}", e.line, e.reason);
//!                         code = 1;
//!                         continue;
//!                     }
//!                     Err(e) => {
//!                         let _ = writeln!(stderr, "rpt-manual: {e}");
//!                         return 1;
//!                     }
//!                 };
//!                 let mut line = rec.raw;
//!                 if rec.kind == "finding" {
//!                     line = set_member(&line, "source", "manual").expect("a record is an object");
//!                 }
//!                 if writeln!(stdout, "{line}").is_err() {
//!                     return 1;
//!                 }
//!             }
//!             code
//!         },
//!     ))
//! }
//! ```
//!
//! Versioning: the crate's version is rpt's, so 0.2.0 goes with rpt v0.2.0. The record format
//! is versioned separately by `schema_version`: adding a field keeps it; renaming or removing
//! one bumps it after a deprecation release.

mod call;
mod json;
mod member;
mod plugin;
mod record;
mod stream;

pub use call::{Call, Error, Output, emit, settings};
pub use member::set_member;
pub use plugin::{Description, Plugin, Range, Requires, Schemas, bin, main, role, run};
pub use record::*;
pub use stream::{LineError, MAX_LINE, ReadError, Rec, Records, records};

# rpt

rpt is a pentest report engine: a report is a plain, git-tracked folder, and the rpt core defines and enforces its format.

## Report

**Report**:
A plain folder holding one engagement's config, scope and findings; the only state rpt has. It may be version-controlled by whoever owns it, but rpt never requires that.
_Avoid_: project, engagement folder, workspace

**Report root**:
The top folder of a report, the one that holds `rpt.yaml`.
_Avoid_: report dir, base dir

**Report config**:
The `rpt.yaml` file at the report root: format version, name, client, period and severity levels.
_Avoid_: settings, rpt.toml

**Format version**:
The `format` number in the report config, telling rpt which version of the report format a folder follows.
_Avoid_: schema version (that numbers the record schemas)

## Findings

**Finding**:
One issue found during the test, stored as one markdown file with YAML frontmatter.
_Avoid_: issue, vuln, vulnerability

**Evidence**:
A file inside the report that backs a finding, listed in the finding's frontmatter relative to the finding file.
_Avoid_: asset (that is evidence as an absolute path in an assembled report), attachment

**Staged finding**:
A finding added by automation, in `staging/`, awaiting review.
_Avoid_: draft, pending finding

**Promote**:
Move a staged finding's file into `findings/`, accepting it into the report.
_Avoid_: approve, accept, publish

**Rejected finding**:
A staged finding judged false, moved to `rejected/` so automation never adds it again.
_Avoid_: deleted finding, false positive (that is the reason, not the state)

**Finding ID**:
A finding's permanent name, `F-` and a number, cited by clients and retests.
_Avoid_: finding number, ref

**Finding key**:
A hash an automated finding carries so re-runs of the same check update it instead of adding a duplicate.
_Avoid_: stable ID, hash ID, fingerprint

**Severity level**:
One of the levels listed in the report config, most severe first; the list is both the sort order and the only allowed values.
_Avoid_: rating, risk, priority

**Summary**:
The number of findings at each severity level, computed when a report is assembled.
_Avoid_: stats, totals

## Core and plugins

**Core**:
The `rpt` binary and its built-in verbs, which only define and enforce the report format.
_Avoid_: engine (alone), server

**Plugin**:
A separate `rpt-<verb>` program that does anything beyond the format: parsing, rendering, knowledge base, detection.
_Avoid_: extension, addon, module

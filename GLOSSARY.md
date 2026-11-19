# rpt

rpt is a pentest report engine: a report is a plain folder, and the rpt core defines and enforces its format.

## Report

**Report**:
A plain folder holding a report's config, scope and findings; the only state rpt has. Engagement details (client, dates, title) belong to whatever manages the project, not to the report. It may be version-controlled by whoever owns it, but rpt never requires that.
_Avoid_: project, engagement folder, workspace

**Report root**:
The top folder of a report, the one that holds `rpt.yaml`.
_Avoid_: report dir, base dir

**Report config**:
The `rpt.yaml` file at the report root: format version, severity levels, required sections and the fixed sections' headings.
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

**Finding ID**:
A finding's permanent name, `F-` and a number, cited by clients and retests.
_Avoid_: finding number, ref

**Target**:
The host, port and protocol a finding was actually found on.
_Avoid_: asset, affected host (in data), endpoint

**Scope row**:
One entry of the agreed scope in `scope.csv`: a host, address range or wildcard domain, optionally narrowed by port and protocol.
_Avoid_: scope item, asset, in-scope host

**Fixed section**:
One of the three sections rpt knows by key: `description`, `remediation`, `poc`. A report may rename its heading in the report config; records always carry the key.
_Avoid_: standard section, built-in section

**Required section**:
A section every finding must have and fill in, listed in the report config; by default description, remediation and proof of concept.
_Avoid_: mandatory field, template section

**Problem**:
One broken rule found in a report, at a file and, when known, a line; an error or a warning.
_Avoid_: lint error, issue, violation

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
A separate `rpt-<verb>` program, in any language, that follows the plugin protocol and does anything beyond the format: parsing, rendering, knowledge base, detection.
_Avoid_: extension, addon, module

**Stock plugin**:
A plugin shipped in rpt-plugins. It reads the report only through the core and never parses report files itself.
_Avoid_: official plugin, built-in plugin (built-ins are verbs)

**Community plugin**:
A third-party plugin vouched for as trusted, held to the same rules as a stock plugin.
_Avoid_: external plugin, contrib

**Local plugin**:
A plugin a user keeps for themselves; the protocol binds it, but it may read report files any way it likes.
_Avoid_: private plugin, custom plugin

**Checker**:
A plugin that emits problems under its own rule names, located at file lines the core gives it.
_Avoid_: linter, validator (that is `rpt validate`)

**Finding lines**:
Where a finding's frontmatter keys and sections sit in its file, as the core reports them.
_Avoid_: positions, offsets, source map

# rpt

rpt is a pentest report engine: a report is a plain folder, and the rpt core defines and enforces its format.

## Report

**Report**:
A plain folder holding a report's config, scope, pages and findings; the only state rpt has. Engagement details (client, dates, title) belong to whatever manages the project, not to the report. It may be version-controlled by whoever owns it, but rpt never requires that.
_Avoid_: project, engagement folder, workspace

**Report root**:
The top folder of a report, the one that holds `rpt.yaml`.
_Avoid_: report dir, base dir

**Report config**:
The `rpt.yaml` file at the report root: format version, severity levels, required sections, the fixed sections' headings, page order, required pages, rule levels, and each plugin's settings.
_Avoid_: settings (alone), rpt.toml

**Plugin settings**:
A plugin's own section of the report config, under `x-<plugin>`. The core keeps and edits it but never reads it or passes it on.
_Avoid_: plugin config file, `.rpt-plugins.yaml`

**Rev**:
A fingerprint of a finding, page, scope row or the report config as it was read. A write given a rev changes nothing if the thing has changed since.
_Avoid_: version, etag, hash (that is how it's made, not what it's for)

**Format version**:
The `format` number in the report config, telling rpt which version of the report format a folder follows.
_Avoid_: schema version (that numbers the record schemas)

## Findings

**Finding**:
One issue found during the test, stored as one markdown file with YAML frontmatter.
_Avoid_: issue, vuln, vulnerability

**Evidence**:
A file of any type inside the report that backs a finding or page. It is listed in the owner's frontmatter, linked from its text, or both.
_Avoid_: asset (that is evidence as an assembled report gives it), attachment

**Listed evidence**:
Evidence named in a finding's or page's `evidence` list: shown beside the text, like an attachment.
_Avoid_: attached evidence

**Linked evidence**:
Evidence cited by a link in a finding's or page's text. Its caption is the link's text.
_Avoid_: embedded evidence, inline evidence

**Asset**:
Evidence as an assembled report gives it: its reference as written, its path in the report, its absolute file, and its media type.
_Avoid_: evidence (that is the file in the report), attachment

**Orphan evidence**:
A file in an evidence folder, `findings/evidence/` or `pages/evidence/`, that no finding or page lists or links to.
_Avoid_: unused asset, stray file, dangling evidence

**Finding ID**:
A finding's permanent name, `F-` and a number, cited by clients and retests.
_Avoid_: finding number, ref

**Target**:
One place a finding was found on, attributed to a scope row: the row's ID, plus where inside it (a host, for a range row) and optionally a port and protocol. A finding has one or more.
_Avoid_: asset, affected host (in data), endpoint

**Page**:
Report-level prose, such as an executive summary, methodology or conclusions, stored as one markdown file in `pages/`. It has a title and an ID, and the report config orders pages around the findings.
_Avoid_: front matter, chapter, appendix finding

**Page ID**:
A page's permanent name, `P-` and a number. Its title is what readers see.
_Avoid_: page key, slug

**Range row**:
A scope row whose host is a CIDR or `*.domain`, covering many assets; a target on it may name a host inside it. Every other scope row is one asset, named by an address, a name or any text.
_Avoid_: subnet row, wildcard entry

**Scope row**:
One entry of the agreed scope in `scope.csv`: a host, address range or wildcard domain, optionally narrowed by port and protocol.
_Avoid_: scope item, asset, in-scope host

**Section key**:
The name records give a finding's section: a fixed section's key (`poc`), or a custom section's heading as written.
_Avoid_: section ID, section name

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
The `rpt` binary and its built-in commands, which only define and enforce the report format.
_Avoid_: engine (alone), server

**Command**:
Anything `rpt <name>` runs: a built-in or a plugin. Most are a noun (`finding`, `page`, `scope`, `evidence`, `config`) taking an action (`get`, `add`, `remove`, `set`, `unset`).
_Avoid_: verb, module, subcommand (that is the action)

**Plugin**:
A separate `rpt-<command>` program, in any language, that follows the plugin protocol and does anything beyond the format: parsing, rendering, knowledge base, detection.
_Avoid_: extension, addon, module

**Stock plugin**:
A plugin shipped in rpt-plugins. It reads the report only through the core and never parses report files itself.
_Avoid_: official plugin, built-in plugin (built-ins are commands)

**Community plugin**:
A third-party plugin vouched for as trusted, held to the same rules as a stock plugin.
_Avoid_: external plugin, contrib

**Local plugin**:
A plugin a user keeps for themselves; the protocol binds it, but it may read report files any way it likes.
_Avoid_: private plugin, custom plugin

**Checker**:
A plugin that emits problems under its own rule names, located at file lines the core gives it.
_Avoid_: linter, validator (that is `rpt validate`)

**Backend**:
An existing program a plugin runs to do its work, such as a markdown linter or a secret scanner. It knows nothing of rpt; the plugin translates between it and rpt.
_Avoid_: engine (that is the core), plugin (that is the `rpt-<command>` program), dependency

**Finding lines**:
Where a finding sits on disk, as the core reports it: its file's absolute path, and the lines its frontmatter keys and sections are on.
_Avoid_: positions, offsets, source map

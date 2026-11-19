# The rpt report format

A report is a plain folder. rpt reads and checks it; nothing else is stored anywhere. `rpt new <dir>` starts one: it writes `rpt.yaml` with the defaults spelled out, a `scope.csv` holding only its header row, and an empty `findings/`. It refuses a folder that isn't empty or that lies inside another report. [`testdata/fixture`](../testdata/fixture) is a filled-in example.

```
acme-external/
├── rpt.yaml              report config
├── scope.csv             in-scope hosts
└── findings/
    ├── F-001-reflected-xss-in-search.md
    ├── F-003-sql-injection-in-login.md
    └── evidence/
        └── F-003-login.png
```

rpt finds the report from `--report <dir>`, else `$RPT_REPORT_DIR`, else the nearest folder at or above the current one that holds `rpt.yaml`. `rpt ls [dir]` searches the other way: it lists every report at or under a folder, never looking inside a report for another (reports don't nest), and skipping hidden folders and symlinks.

The report holds the findings, not the engagement: client name, dates and title belong to whatever manages the project, and renderers take them as their own input.

## `rpt.yaml`

```yaml
format: 1
severities: [critical, high, medium, low, info]
required_sections: [description, remediation, poc]
sections:
  remediation: Recommendation
```

| Key | Required | Meaning |
| --- | --- | --- |
| `format` | yes | Report format version. `1` is the only one. |
| `severities` | no | The allowed levels, most severe first. It is also the order findings are sorted in. Default: `critical, high, medium, low, info`. Any names work, e.g. `[urgent, normal]`. |
| `required_sections` | no | Sections every finding must have, non-empty. Default: `description, remediation, poc`. `[]` requires none. A fixed section is listed by its key or its heading; a custom one by its exact text. |
| `sections` | no | Renames fixed sections: maps `description`, `remediation` or `poc` to the heading this report uses for it. Unnamed ones keep their default heading. Records and renderers still see the fixed key, whatever the heading. |

Other keys are warned about by `rpt validate` and never reach the assembled report.

## `scope.csv`

```csv
id,host,port,protocol,env
S-12,10.0.0.5,443,tcp,prod
S-20,10.0.1.0/24,,,staging
S-30,*.acme.com,,,prod
```

- The header row must name `id` and `host`. `port` and `protocol` (`tcp` or `udp`) are optional. Any other column is kept and passed to renderers.
- Every row needs an id and a host; ids don't repeat.
- `host` is an address, a name, a CIDR range, or `*.domain` for any subdomain.
- A report with no scope has a `scope.csv` holding only its header row.

## Findings

One markdown file per finding, directly in `findings/`, with YAML frontmatter:

```markdown
---
id: F-003
title: SQL injection in login
scope: [S-12, S-14]
severity: high
evidence: [evidence/F-003-login.png]
target: {host: 10.0.0.5, port: 443, protocol: tcp}
cvss: "9.1"
---
## Description

The `user` parameter of `/login` is concatenated into a SQL query.

## Remediation

Use parameterised queries.

## Proof of concept

![login bypass](evidence/F-003-login.png)
```

| Field | Meaning |
| --- | --- |
| `id` | `F-` and at least three digits, unique in the report. It is the finding's permanent name. A new finding takes the highest number plus one. |
| `title` | One line. |
| `scope` | IDs of the `scope.csv` rows the finding affects. |
| `severity` | One of the config's `severities`. |
| `evidence` | Files backing the finding, relative to the finding file. They must stay inside the report. |
| `target` | Optional: the `host`, `port` and `protocol` it was found on. `rpt scope match` uses it to fill in `scope`. |
| anything else | Kept as is and passed to plugins and renderers, e.g. `cvss`. Not `kind`, `path`, `sections` or `lines`: rpt sets those on finding records, so a file using one is unreadable. |

The body is split into sections at `##` headings. `## Description`, `## Remediation` and `## Proof of concept` are the fixed sections (keys `description`, `remediation`, `poc`), unless `sections` in `rpt.yaml` renames them. A fixed heading matches whatever its case: `## Proof Of Concept` is `poc`. Any other `##` heading is kept under its own text, exactly. `rpt add` writes the report's headings. `##` lines inside code fences are not headings. Text before the first heading belongs to no section. Images and links to report files count as evidence and are checked the same way.

The file name is free. `rpt add` names new files `F-NNN-<title-slug>.md`.

## `rpt validate` rules

`rpt validate` prints one problem per broken rule, with the file and line, and exits 1 if any is an error. The rule names are stable, so scripts and CI can filter on them.

| Rule | Level | Checks |
| --- | --- | --- |
| `readable` | error | Each file parses: valid YAML frontmatter with no reserved key, valid CSV. |
| `findingID` | error | Every finding has an `id` of the form `F-NNN`, and no two share one. The message names the next free ID. |
| `title` | error | Every finding has a title. |
| `knownSeverity` | error | Every severity is one of the config's `severities`. |
| `scopeIDsExist` | error | Every scope ID a finding lists is in `scope.csv`. |
| `requiredSections` | error | Every finding has each required section, and it isn't empty. |
| `evidence` | error | Every evidence file and linked file stays inside the report, exists, and is a regular file. |
| `config` | error | `format` is 1; `severities` and `required_sections` have no empty or repeated names, and `severities` isn't empty; `sections` renames only fixed sections, to non-empty headings, no two alike. |
| `scope` | error | `scope.csv` exists, has `id` and `host` columns, and every row has a unique id and a host. |
| `textBeforeHeading` | warning | Text before a finding's first `##` heading, which no section holds. |
| `configUnknownKey` | warning | A key in `rpt.yaml` that rpt doesn't define. |

Plugins can check more by emitting problems under their own rule names.

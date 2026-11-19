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

rpt finds the report from `--report <dir>`, else `$RPT_REPORT_DIR`, else the nearest folder at or above the current one that holds `rpt.yaml`. `rpt ls --current` prints the report those rules pick, as one `location` record with its absolute path; it exits 1 when they find none, or when `--report` or `$RPT_REPORT_DIR` names a folder without `rpt.yaml`. `rpt ls [dir]` searches the other way: it lists every report at or under a folder, never looking inside a report for another (reports don't nest), and skipping hidden folders and symlinks.

The report holds the findings, not the engagement: client name, dates and title belong to whatever manages the project, and renderers take them as their own input.

## `rpt.yaml`

```yaml
format: 2
severities: [critical, high, medium, low, info]
required_sections: [description, remediation, poc]
sections:
  remediation: Recommendation
```

| Key | Required | Meaning |
| --- | --- | --- |
| `format` | yes | Report format version. `2` is the only one rpt reads. Format 1 gave findings `scope` and `target`, which format 2 replaced with `targets`. |
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

- The header row must name `id` and `host`. `port` and `protocol` (`tcp` or `udp`) are optional. Any other column is kept and passed to renderers, except that no column may be named `kind` or `lines`: rpt sets those on scope records, so a `scope.csv` using one is unreadable.
- Every row needs an id and a host; ids don't repeat.
- `host` is a CIDR range or `*.domain` (any subdomain, not the bare domain), which are **ranges**, or anything else, which is **one asset**: an address, a name, or any text that names what's in scope, such as `Acme iOS app` or `github.com/acme/api`.
- A report with no scope has a `scope.csv` holding only its header row.

## Findings

One markdown file per finding, directly in `findings/`, with YAML frontmatter:

```markdown
---
id: F-003
title: SQL injection in login
targets:
  - {scope: S-12, port: 443, protocol: tcp}
  - {scope: S-20, host: 10.0.1.7, port: 8443}
severity: high
evidence: [evidence/F-003-login.png]
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
| `targets` | Where the finding was found, each attributed to a scope row: see Targets below. Every finding needs at least one. |
| `severity` | One of the config's `severities`. |
| `evidence` | Files backing the finding, relative to the finding file. They must stay inside the report. |
| anything else | Kept as is and passed to plugins and renderers, e.g. `cvss`. Not `kind`, `path`, `sections` or `lines`: rpt sets those on finding records, so a file using one is unreadable. Nor `scope` or `target`, format 1's keys. |

### Targets

A finding is always attributed to scope: each target names the `scope.csv` row it falls in, so it can never point at something outside the agreed scope.

| Key | Meaning |
| --- | --- |
| `scope` | Required: the ID of the scope row. |
| `host` | Only for a range row (a CIDR or `*.domain`), to say where inside it, such as `10.0.1.7` in `10.0.1.0/24`. Absent, the target is the whole range. Not allowed on a row that is one asset: the row already says which. |
| `port`, `protocol` | Optional. When the row has a port or protocol, the target's must equal it. |

Unknown keys in a target are kept, like unknown frontmatter keys. A finding found on many hosts lists one target per host, or the whole range once.

A parser plugin doesn't know the report's scope, so it writes targets with a `host` and no `scope`. `rpt scope match` attributes each one to the most specific row that covers it: one asset before a range, a narrower CIDR before a wider one, any CIDR before a `*.domain`, a longer `*.domain` before a shorter one, then a row with a port, then a row with a protocol, then the lower ID. It drops the host when that row is one asset. `rpt findings add` refuses a target without a scope ID.

The body is split into sections at `##` headings. `## Description`, `## Remediation` and `## Proof of concept` are the fixed sections (keys `description`, `remediation`, `poc`), unless `sections` in `rpt.yaml` renames them. A fixed heading matches whatever its case: `## Proof Of Concept` is `poc`. Any other `##` heading is kept under its own text, exactly. `rpt findings add` and `rpt sections set` write the report's headings. `##` lines inside code fences are not headings. Text before the first heading belongs to no section. Images and links to report files count as evidence and are checked the same way.

The file name is free. `rpt findings add` names new files `F-NNN-<title-slug>.md`.

Evidence files can sit anywhere inside the report, but `findings/evidence/` is where `rpt evidence add` puts them. It names each copy `<id>-<slug>.<ext>`: the slug is the source file's name without its extension, lowercased, with each run of other characters than `a`–`z` and `0`–`9` turned into one `-`, at most 40 characters, or `evidence` if nothing is left; the extension is lowercased. A name that's taken gets `-2`, `-3` and so on. A file in `findings/evidence/` that no finding lists or links to is an orphan: `rpt validate` warns about it, and `rpt evidence prune` removes it. Hidden files there, such as `.gitkeep`, are left alone.

## `rpt validate` rules

`rpt validate` prints one problem per broken rule, with the file and line, and exits 1 if any is an error. The rule names are stable, so scripts and CI can filter on them.

| Rule | Level | Checks |
| --- | --- | --- |
| `readable` | error | Each file parses: valid YAML frontmatter with no reserved key, valid CSV. |
| `findingID` | error | Every finding has an `id` of the form `F-NNN`, and no two share one. The message names the next free ID. |
| `title` | error | Every finding has a title. |
| `knownSeverity` | error | Every severity is one of the config's `severities`. |
| `scopeIDsExist` | error | Every scope ID a finding's targets name is in `scope.csv`. |
| `targets` | error | Every finding has at least one target; each names a scope row, and fits it: a host only inside a range row, and the row's port and protocol if it has them. |
| `requiredSections` | error | Every finding has each required section, and it isn't empty. |
| `evidence` | error | Every evidence file and linked file stays inside the report, exists, and is a regular file. |
| `config` | error | `format` is 2; `severities` and `required_sections` have no empty or repeated names, and `severities` isn't empty; `sections` renames only fixed sections, to non-empty headings, no two alike. |
| `scope` | error | `scope.csv` exists, has `id` and `host` columns, and every row has a unique id and a host. |
| `textBeforeHeading` | warning | Text before a finding's first `##` heading, which no section holds. |
| `configUnknownKey` | warning | A key in `rpt.yaml` that rpt doesn't define. |
| `evidenceUnlinked` | warning | A file in `findings/evidence/` that no finding lists or links to. Not checked while a finding file is unreadable. |

Plugins can check more by emitting problems under their own rule names.

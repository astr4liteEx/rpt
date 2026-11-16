---
id: F-003
title: SQL injection in login
scope: [S-12, S-14]   # both login front-ends
severity: high
evidence: [evidence/F-003-login.png]
cvss: "9.1"
---
## Description

The `user` parameter of `/login` is concatenated into a SQL query.

## Remediation

Use parameterised queries.

## Proof of concept

```sh
## not a heading: inside a code fence
curl -d "user=' OR 1=1--" https://10.0.0.5/login
```

![login bypass](evidence/F-003-login.png)

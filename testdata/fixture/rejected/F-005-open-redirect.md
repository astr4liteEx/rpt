---
id: F-005
key: 01b9b837704da8cf
title: Open redirect in logout
scope: [S-14]
severity: low
target: {host: 10.0.0.6, port: 8443, protocol: tcp}
---
## Description

The `next` parameter of `/logout` redirects anywhere.

## Remediation

Allow only relative redirects.

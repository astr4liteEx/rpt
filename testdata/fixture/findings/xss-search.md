---
id: F-001
title: Reflected XSS in search
targets: [{scope: S-14, port: 8443, protocol: tcp}]
severity: medium
---

## Description

The `q` parameter is reflected unescaped.

## Remediation

Encode output.

## Proof of concept

`/search?q=<script>alert(1)</script>`

## References

- OWASP XSS Prevention Cheat Sheet

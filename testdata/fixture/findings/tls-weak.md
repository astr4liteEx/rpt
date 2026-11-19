---
id: F-002
title: Weak TLS configuration
# Planted problem: S-99 is not in scope.csv. rpt validate must catch it.
scope: [S-99]
severity: info
---

## Description

TLS 1.0 is still enabled.

## Remediation

Disable TLS 1.0 and 1.1.

## Proof of concept

`nmap --script ssl-enum-ciphers -p 443 10.0.0.5`

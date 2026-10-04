# Security Policy

## Reporting a vulnerability in airteam

Please report vulnerabilities in the scanner itself privately via GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab). Do not open a public issue. Expect an acknowledgement within 7 days.

## Scope of the tool

- airteam is for **authorized** testing only. Configurations must declare an authorization mode and host scope; endpoints outside scope are refused.
- The bundled playground is intentionally vulnerable and must only be run locally.
- Public demonstrations use synthetic identities, data and canary secrets only.

## Scanner hardening rules (spec §32)

The scanner never executes model output, trusts model-generated paths, writes files from untrusted content, follows arbitrary URLs, logs raw secrets by default, or loads plugins via dynamic code execution.

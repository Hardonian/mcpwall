# Security Policy

## Supported versions

Security fixes target the latest tagged release and `main`.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub Security Advisories for this repository when available, or contact the repository maintainer privately through the GitHub profile at https://github.com/Hardonian.

Include:

- affected version or commit
- reproducible configuration and request shape
- expected versus observed security boundary
- logs with secrets and customer data removed

Do not include credentials, private keys, tokens, personal data, or live customer payloads.

## Scope

mcpwall is a local stdio policy proxy. It does not protect against a compromised host, root, kernel compromise, or a fully compromised child process. Optional Linux sandbox controls fail closed when requested isolation is unavailable, but they are not a substitute for a container or VM boundary.

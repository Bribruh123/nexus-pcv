# 0.3.0

- Add support for Nexus Dashboard (ND) 4.2.1+ using the unified Analyze API for pre-change validation
- Authenticate via `/api/v1/infra/login` and send the JWT as a bearer token (required for write operations)
- Resolve the target DN (`tDn`) for relation objects with a bracketed DN target, required by ND schema validation
- Report new pre-change anomalies grouped by severity
- Report anomalies raised and cleared by the change with per-anomaly details (type, severity, description, nodes, mnemonic)
- Show progress by default (verbosity `INFO`) while suppressing HTTP client noise
- Add a static class name mapping for the `mgmtp` (management profile) RN prefix

# 0.2.1

- Fix issue with Terraform resource attributes set to `null`

# 0.2.0

- Drop support for NAE (Network Assurance Engine)
- Drop support for Python 3.7
- Add support for Python 3.11 and 3.12
- Use `default` as default NDI group

# 0.1.6

- Update NDI anomaly query URL to work with ND 3.0+

# 0.1.5

- Further improve resolution of missing classnames and key attributes

# 0.1.4

- Improve resolution of missing classnames and key attributes

# 0.1.3

- Fix overlapping CLI arguments (`-s` and `-t`)

# 0.1.2

- Fix URL output for NDI

# 0.1.1

- Fix error handling and exit codes

# 0.1.0

- Initial release

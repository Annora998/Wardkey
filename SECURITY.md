# Security

## Status

Wardkey is an experimental project and is not production ready. Do not use it to protect production credentials. In particular, Wardkey does not claim to protect against a compromised Windows operating system, malicious code running with the same user's privileges, credential exposure after a legitimate application receives a credential, or compromise of the development/build environment.

Wardkey currently implements an encrypted vault, local policy enforcement, Windows process identity checks, Windows Hello approval, Git credential handling, AWS CLI credential_process handling, and a local HMAC-chained audit log. These controls have limitations and have not been independently security reviewed.

Use dummy credentials for testing.

## Security policy

Do not use this scaffold to store or broker real credentials. No vault, trusted caller identity, authenticated approval, or credential provider is implemented. Report security issues privately to the maintainers once a public contact is established. Never include secrets in reports. Please do not include real credentials, passphrases, private keys, or other secrets in reports.

## Reporting a vulnerability

Please email **[annora998@gmail.com](mailto:annora998@gmail.com)** with a description, reproduction steps, and affected version or commit. Do not include real credentials, passphrases, private keys, or other secrets.

I aim to acknowledge reports within three calendar days.

## Supported versions

Only the latest `main` branch is intended to receive security fixes. No tagged release currently has a support commitment.

See [README.md](README.md) for an implementation overview and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for security boundaries and limitations.

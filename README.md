# Wardkey

Wardkey is an experimental local credential broker for Git and the AWS CLI on Windows. It stores credentials in an encrypted vault, applies local policy to every request, and can require Windows Hello approval before releasing a credential.

> **Warning:** This is a research prototype. Use **dummy credentials only** for testing. It has not had an independent cryptographic or security review.

## Overview

Developer credentials are usually accessed through tools such as Git and the AWS CLI. Normally, any program running as your Windows user can ask for them.

Wardkey explores whether credential release can depend not only on the Windows user, but also on **which application is asking**. Before releasing anything, the prototype evaluates the requesting process, the credential provider/profile, and local policy. Optional Windows Hello approval adds an explicit user confirmation step.

**Without application-aware control**

```
User -> Credential helper -> Credential
```

**With Wardkey**

```
Application -> Wardkey -> Process identity -> Policy -> Allow / Deny / Approval -> Credential
```

## Features

- Encrypted vault for credential entries.
- Local broker and Git credential helper for Git credential requests.
- AWS CLI support through `credential_process`.
- Caller and profile policy, with per-request Windows Hello approval when configured.
- Local, HMAC-chained audit log of every decision.
- Decoy entries that are always denied and logged when requested.

## How it works

Every request follows the same pipeline:

```
Git credential helper / AWS credential_process
        |
        v
Windows named pipe
        |
        v
OS-derived peer PID
        |
        v
Handler.Handle()
        |
        v
Credential request validation
        |
        v
Caller identity and process verification --- invalid ---> reject + audit
        |
        v
Decoy check ------------------------------- decoy -----> deny + audit
        |
        v
Policy evaluation ------------------------- DENY -------> deny + audit
        |
        +--- APPROVAL REQUIRED
        |         |
        |         v
        |    Request-bound Windows Hello approval
        |         |
        |         v
        |    Assertion verification --------- fail -----> deny + audit
        |         |
        +--- ALLOW (or approval passed)
                  |
                  v
          Session.WithCredential()
                  |
                  v
          Git / AWS executor
                  |
                  v
          Audit decision and result
                  |
                  v
          Git / AWS credential response
```

## Technology

| Area | Details |
| --- | --- |
| Language | Go |
| OS integrations | Windows named pipes, Windows ACLs, process inspection, Windows WebAuthn / Windows Hello |
| Vault encryption | Argon2id key derivation and XChaCha20-Poly1305 |
| Argon2id parameters | Time cost 3, 64 MiB memory, parallelism 4 (as in the vault format code shared during development) |
| Audit key | Dedicated key derived from the vault data key using HKDF-SHA256 |
| Audit integrity | HMAC-chained records stored locally |

These are implementation details, not a claim of independent cryptographic review.

## Getting started

### Requirements

- Windows
- Go toolchain
- Windows Hello set up (only needed if you use approval-required policies)

### Build

```powershell
go build -o wardkey.exe .\cmd\wardkey
```

### Test

```bash
go test ./...
```

Automated tests cover the implemented security and request-handling components.

## Security

Wardkey is experimental and has known limitations. Please read:

- [SECURITY.md](SECURITY.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

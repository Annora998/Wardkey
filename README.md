# Wardkey

Wardkey is an experimental local credential broker for Git and the AWS CLI on Windows. It stores credentials in an encrypted vault, applies local policy to requests, and can require Windows Hello approval.

Developer credentials are commonly accessed through tools such as Git and the AWS CLI. Wardkey explores whether credential release can be made dependent not only on the Windows user, but also on the application requesting the credential. The prototype evaluates the requesting process, credential provider/profile, and local policy before releasing a credential. Optional Windows Hello approval can add an explicit user confirmation step.

**Use dummy credentials for testing.**

## How it works

```
START
  ↓
Git credential helper / AWS credential_process
  ↓
Windows Named Pipe
  ↓
OS-derived peer PID
  ↓
Handler.Handle()
  ↓
Credential request validation
  ↓
Caller identity & process verification
  │
  ├── invalid → reject + audit
  │
  ↓
Decoy check
  │
  ├── decoy → deny + audit
  │
  ↓
Policy evaluation
  │
  ├── DENY → deny + audit
  │
  ├── APPROVAL REQUIRED
  │     ↓
  │   Request-bound Windows Hello approval
  │     ↓
  │   assertion verification
  │     │
  │     └── fail → deny + audit
  │
  └── ALLOW
        ↓
      Session.WithCredential()
        ↓
      Git / AWS executor
        ↓
      audit decision/result
        ↓
      Git / AWS credential response
        ↓
      END
```

## The idea

Without application-aware control:

```
User
  ↓
Credential helper
  ↓
Credential
```

With Wardkey:

```
Application
  ↓
Wardkey
  ↓
Process identity
  ↓
Policy
  ↓
Allow / Deny / Approval
  ↓
Credential
```

Wardkey is an experimental implementation of this application-aware credential-release model for Git and AWS CLI.

## What it does

- Stores credential entries in an encrypted vault.
- Serves Git credential requests through a local broker and Git credential helper.
- Supplies AWS credentials through AWS CLI `credential_process`.
- Applies caller and profile policy, with per-request Windows Hello approval when configured.
- Records decisions in a local, HMAC-chained audit log.
- Supports decoy entries that are denied and logged when requested.

## Technology

| Area | Details |
| --- | --- |
| **Language** | Go. |
| **Operating-system integrations** | Windows named pipes, Windows ACLs, process inspection, and Windows WebAuthn / Windows Hello. |
| **Vault encryption** | Argon2id and XChaCha20-Poly1305. The vault format code shared during development uses Argon2id parameters of time cost 3, 64 MiB memory, and parallelism 4. |
| **Audit key** | HKDF-SHA256 derives a dedicated audit key from the vault data key. |
| **Audit integrity** | HMAC-chained records stored locally. |

These are implementation details, not a claim of independent cryptographic review. See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for limitations.

## Current limits

- **AWS:** Wardkey works only with the official AWS command-line tool (`aws.exe`). Other tools, such as Terraform or programming libraries, are not supported yet.
- **AWS prompts:** Wardkey does not remember AWS credentials between calls. If a rule asks for Windows Hello every time, you may be asked often.
- **Windows only.** There is no Mac or Linux version.
- **Not independently audited.** Do not use this to protect anything you cannot afford to lose.
  

## Getting started

### Requirements

- Windows
- Go toolchain
- Windows Hello set up (only needed if you use approval-required policies)

### Build

```
go build -o wardkey.exe .\cmd\wardkey
```

### Test

```
go test ./...
```

Automated tests cover the implemented security and request-handling components.

## Security

Wardkey is experimental and has known limitations. Please read:

- [SECURITY.md](https://github.com/Annora998/Wardkey/blob/master/SECURITY.md)
- [docs/THREAT_MODEL.md](https://github.com/Annora998/Wardkey/blob/master/docs/THREAT_MODEL.md)

\# Wardkey



Wardkey is an experimental local credential broker for Git and the AWS CLI on Windows. It stores credentials in an encrypted vault, applies local policy to requests, and can require Windows Hello approval.



Developer credentials are commonly accessed through tools such as Git and the AWS CLI. Wardkey explores whether credential release can be made dependent not only on the Windows user, but also on the application requesting the credential.The prototype evaluates the requesting process, credential provider/profile, and local policy before releasing a credential. Optional Windows Hello approval can add an explicit user confirmation step.



\*\* Use dummy credentials for testing.\*\*



\## How it works

START

&#x20; ↓

Git credential helper / AWS credential\_process

&#x20; ↓

Windows Named Pipe

&#x20; ↓

OS-derived peer PID

&#x20; ↓

Handler.Handle()

&#x20; ↓

Credential request validation

&#x20; ↓

Caller identity \& process verification

&#x20; │

&#x20; ├── invalid → reject + audit

&#x20; │

&#x20; ↓

Decoy check

&#x20; │

&#x20; ├── decoy → deny + audit

&#x20; │

&#x20; ↓

Policy evaluation

&#x20; │

&#x20; ├── DENY → deny + audit

&#x20; │

&#x20; ├── APPROVAL REQUIRED

&#x20; │       ↓

&#x20; │   Request-bound Windows Hello approval

&#x20; │       ↓

&#x20; │   assertion verification

&#x20; │       │

&#x20; │       └── fail → deny + audit

&#x20; │

&#x20; └── ALLOW

&#x20;         ↓

&#x20;  Session.WithCredential()

&#x20;         ↓

&#x20;  Git / AWS executor

&#x20;         ↓

&#x20;  audit decision/result

&#x20;         ↓

&#x20;  Git / AWS credential response

&#x20;         ↓

&#x20;        END





\## The idea





Without application-aware control:



User

&#x20;↓

Credential helper

&#x20;↓

Credential







With Wardkey:



Application

&#x20;↓

Wardkey

&#x20;↓

Process identity

&#x20;↓

Policy

&#x20;↓

Allow / Deny / Approval

&#x20;↓

Credential



Wardkey is an experimental implementation of this application-aware credential-release model for Git and AWS CLI.





\## What it does



\- Stores credential entries in an encrypted vault.

\- Serves Git credential requests through a local broker and Git credential helper.

\- Supplies AWS credentials through AWS CLI `credential\_process`.

\- Applies caller and profile policy, with per-request Windows Hello approval when configured.

\- Records decisions in a local, HMAC-chained audit log.

\- Supports decoy entries that are denied and logged when requested.





\## Technology



\- \*\*Language:\*\* Go.

\- \*\*Operating-system integrations:\*\* Windows named pipes, Windows ACLs, process inspection, and Windows WebAuthn / Windows Hello.

\- \*\*Vault encryption:\*\* Argon2id and XChaCha20-Poly1305. The vault format code shared during development uses Argon2id parameters of time cost 3, 64 MiB memory, and parallelism 4.

\- \*\*Audit key:\*\* HKDF-SHA256 derives a dedicated audit key from the vault data key.

\- \*\*Audit integrity:\*\* HMAC-chained records stored locally.



These are implementation details, not a claim of independent cryptographic review. See \[SECURITY.md](SECURITY.md) and \[docs/THREAT\_MODEL.md](docs/THREAT\_MODEL.md) for limitations.





\## Testing



Automated tests are included for the implemented security and request-handling components.



Run the test suite with:



```powershell

go test ./...





\## Development



Build the main executable:



```powershell

go build -o wardkey.exe .\\cmd\\wardkey


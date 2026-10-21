# Wardkey Threat Model

## Status and scope

Wardkey is experimental. This document describes the intended local Windows use of the current implementation. It is not an independent security review or a guarantee that every threat is prevented.

Wardkey is designed to broker credentials for Git and the AWS CLI on one Windows user account. Its controls can restrict and record credential requests that pass through Wardkey and record the resulting decisions in the local audit log.

## Assets

- Credentials stored in the encrypted vault.

- Vault and audit key material while the broker is unlocked.

- Policy and Windows Hello approval configuration.

- Audit history describing credential decisions.

## Security controls

- The vault uses Argon2id and XChaCha20-Poly1305. The format code shared during development configures Argon2id with time cost 3, 64 MiB memory, and parallelism 4.

- A dedicated audit key is derived from the vault data key using HKDF-SHA256. The audit log uses a chained HMAC to detect many forms of local record modification.

- The broker uses a current-user Windows named pipe and checks caller process information and executable hashes before evaluating policy.

- Policies can require Windows Hello approval for each request. Approval challenges are bound to request data; tests cover replay rejection, and the Windows Hello spike verified an assertion signature, relying-party hash, and user-verification flags.

- Decoy credential requests are denied and audited. Automated broker tests and a dummy-credential Git helper check cover this behavior.

- Development mode prints a warning that it is for dummy credentials and may not enforce Windows file permissions.

These controls have limits described below. Their presence does not establish that Wardkey is safe for production use.

## Trust boundaries and limitations

### Same-user processes

Wardkey runs within the logged-in Windows user’s security boundary. Malware running as that user may launch legitimate applications, interact with Wardkey, modify user-accessible files, or access credentials after Wardkey releases them to an application.

Executable hashes and parent-process checks do not prove that a human initiated a request or that the application’s entire process lineage is trustworthy.

### Windows Hello

Windows Hello approval requires user verification through the Windows WebAuthn flow. It depends on Windows, the device, and the integrity of Wardkey. It does not protect against a compromised operating system, malicious code in the same user session, coercion, or approval of a misleading prompt.

### Vault, memory, and backups

The vault is encrypted at rest, but credentials and key material must be available in memory while in use. The program clears owned buffers where possible; Go or the operating system may retain copies.

The vault key is not currently bound to a TPM or another hardware-backed key store. A copied vault and its passphrase may be usable on another compatible system. There is no external anti-rollback service or hardware counter, so restoring older valid vault or audit files may restore older state.

### Audit log

The HMAC chain can detect many edits when verified with the correct key. The log is local and is not an independent remote record. An attacker able to access the relevant key material or restore older files may defeat or roll back the evidence. The log does not provide nonrepudiation.

### Decoys

Wardkey denies and logs decoy requests that reach its implemented credential-request path. Decoys do not detect an attacker who avoids Wardkey or obtains a real credential through another channel.

### Platform and development mode

The current design relies on Windows ACLs, named pipes, and Windows Hello. Do not assume equivalent protections on other platforms.

Development mode is for dummy test credentials only. Its warning states that the selected location may not enforce Windows file permissions.

### Build and release integrity

Matching hashes show that the two local executable files were identical when hashed. This does not verify the source, build environment, dependencies, publisher identity, or distribution channel. Wardkey does not yet provide a complete signed release and update-verification process.

## Production-readiness work

Before production use, Wardkey needs independent security review, a verifiable signed release and update process, documented recovery and incident response, and review of migration, backup, permissions, and rollback behavior.

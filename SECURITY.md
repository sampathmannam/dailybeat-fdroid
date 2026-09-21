# Security and trust

Report DailyBeat application vulnerabilities privately through the
[application's security policy](https://github.com/sampathmannam/dailybeat/security/policy).
Do not include location history, journal contents, backups, passwords or signing
keys in a public issue. Use that same private reporting channel for distribution
integrity concerns.

The repository certificate authenticates its catalog. Android separately checks
the existing DailyBeat APK certificate. These keys are intentionally different.
The repository signing workflow must never receive the application's private key.

Public artifacts are checked against a strict publication allowlist and pinned
release identities. This reduces accidental or substituted releases; it does not
make malicious changes by a fully compromised maintainer account impossible.
Protect the GitHub account with strong multi-factor authentication, review workflow
changes, and keep an offline recovery copy of the repository key and password.

If the private repository key or CI credentials are exposed, stop publishing,
investigate the incident, preserve evidence, and notify subscribers with replacement
trust instructions. Never silently regenerate the identity or conceal a compromise.

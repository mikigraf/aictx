# Security policy

## Supported versions

Before the first stable release, security fixes are made on the latest `0.2.x` line only. Upgrade to the newest patch release before reporting a problem that may already be fixed.

| Version | Supported |
| --- | --- |
| latest `0.2.x` | yes |
| `aictx` `0.1.x` and older builds | no |

No deployment should treat the current implementation as qualified for its OS, native keyring, and vendor versions without completing the checks in [docs/compatibility.md](docs/compatibility.md).

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include real credentials, vendor state, personal account identifiers, keyring references, or identity-provider details in a report.

After publication, use the repository's **Security → Report a vulnerability** private-advisory flow. Maintainers must enable private vulnerability reporting before the first public release.

If that private channel is unavailable, do not post exploit details publicly. Contact the repository owner through a private channel shown by the published project and request a secure reporting route.

Include only sanitized evidence:

- affected `ctxlane` version/commit and operating system;
- vendor CLI name/version, without account output;
- the security invariant that failed;
- minimal reproduction using fake credentials and, preferably, fake vendor executables;
- expected impact and whether the issue is already public;
- any suggested mitigation.

Maintainers should acknowledge a complete report within seven calendar days, coordinate remediation and disclosure privately, and credit the reporter if requested. This is a response target, not a paid bug-bounty promise.

## High-priority issue classes

- a secret appears in stdout/stderr, wrapper configuration/state, argv, generated shell code, completions, or normal diagnostics, or vendor-cached state escapes its isolated profile directory;
- the wrong profile credential or billing domain reaches a vendor child;
- a repository can select a secret, executable, endpoint, or command hook despite policy;
- a symlink, permission, path-search, or concurrency race crosses profile boundaries;
- a public/fork workflow can bypass access-token policy;
- malformed input causes a fail-open credential fallback;
- release provenance, archive contents, or dependency integrity is compromised.

## Handling accidentally disclosed credentials

Treat any real credential included in an issue, log, screenshot, artifact, or test as compromised:

1. revoke or rotate it at the vendor or identity provider;
2. remove public artifacts where possible, while assuming copies exist;
3. inspect account/audit logs and runner history;
4. replace affected local vendor state;
5. report the product defect with a synthetic reproduction.

`ctxlane logout` is local cleanup and is not sufficient remote revocation.

## Release security

The release workflow produces archives, SHA-256 checksums, keyless Sigstore bundles, a CycloneDX JSON SBOM, and GitHub build provenance. Verify the checksum, Sigstore identity/issuer, and provenance before installation. These controls do not imply native Authenticode/Apple code signing or macOS notarization; consumers must not assume either until separately implemented and documented.

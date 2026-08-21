# CI and automation

Automation has a different trust boundary from a developer laptop. `--non-interactive` controls prompts; it does not make a public runner safe for a long-lived credential.

## Credential hierarchy

Use the least-personal credential compatible with the task:

1. Claude WIF for supported cloud/CI identity providers, because the upstream identity token can be exchanged by Anthropic's official client for short-lived access.
2. A pre-authorized Codex OAuth profile only on a tightly controlled private runner where the subscription or workspace identity is required.

Static API keys, subscription tokens, and access tokens are stored in the native OS keyring. `--non-interactive` refuses credential reads, writes, and deletes in the keyring, so these profiles are not a headless CI credential path.

Do not copy a developer's vendor credential cache into a shared runner. `ctxlane` does not implement cache import/export.

## Non-interactive behavior

Global `--non-interactive` refuses an operation that may require:

- browser/device authorization;
- terminal confirmation;
- hidden terminal entry;
- OS-keyring unlock or user consent.

WIF requires the upstream identity-token file to be a private regular file. A cached Codex OAuth profile must be authorized before the non-interactive job starts and must remain isolated to a controlled private runner.

## Codex access-token policy

An access-token profile requires `--workspace` at creation. When inherited `GITHUB_EVENT_NAME` identifies `pull_request` or `pull_request_target`, `ctxlane` refuses wrapper-managed static credentials and cached Codex OAuth before use. That check is defense-in-depth because code in the job can alter its own environment; GitHub job permissions, environment protection, and secret gating must prevent untrusted jobs from receiving credentials in the first place. When `CI` is set or `--non-interactive` is active, Claude subscription-token, Codex OAuth, and Codex access-token runs also require the explicit `ctxlane run --trusted-runner ...` flag. There is no environment-variable equivalent for that assertion because inherited environment is not a trust boundary.

This flag is a deliberate operator assertion, not a technical attestation. Set it only after verifying:

- the runner is private and access-controlled;
- untrusted forks cannot select the credential-bearing job;
- protected branches/environments gate deployment secrets;
- workflow files cannot be changed by an untrusted trigger before secret injection;
- logs and retained artifacts do not contain environment dumps or vendor state;
- employee offboarding and credential rotation are defined.

Never use the assertion to make a public or shared runner appear trusted.

## GitHub Actions pattern

This repository's own CI does not need real vendor credentials. It uses unit tests and fake vendor executables. Workflow actions are pinned to immutable commit revisions; adjacent comments identify the tracked major line so updates can be reviewed deliberately.

For a downstream private workflow, initialize metadata at runtime under an ephemeral absolute `--root`, create profiles and contexts, and use WIF to provide a short-lived identity. Do not commit generated `config.toml`, `state.toml`, identity tokens, or vendor homes.

Conceptual protected-job structure:

```yaml
jobs:
  private-review:
    if: github.event_name != 'pull_request'
    runs-on: [self-hosted, private]
    environment: ai-review-production
    permissions:
      contents: read
      id-token: write # only when the upstream identity provider needs OIDC
    steps:
      - uses: actions/checkout@v4
      - name: Run selected official client
        run: >-
          ctxlane --root "${{ runner.temp }}/ctxlane" --non-interactive run
          --profile claude:ci claude -- -p "review this change"
```

The setup needed to create `claude:ci` is deployment-specific and intentionally omitted. Use your WIF policy, not an inline credential. Pin actions to reviewed commit SHAs in a regulated deployment and keep those pins updated.

## Claude WIF profile

Create the identity-token file through the upstream OIDC/workload identity mechanism, restrict its permissions, then configure selectors:

```bash
ctxlane profile add claude ci \
  --auth wif \
  --organization-id "$ANTHROPIC_ORG_ID" \
  --federation-rule-id "$ANTHROPIC_RULE_ID" \
  --service-account-id "$ANTHROPIC_SERVICE_ACCOUNT" \
  --identity-token-file "$RUNNER_TEMP/anthropic-identity.jwt"
```

`ctxlane` passes the selector names and file path to the official Claude client. It does not contact Anthropic's token endpoint, validate JWT claims, or refresh access tokens itself. Validate this flow with the exact IdP and Claude CLI deployed in your organization.

## Failure handling

Use the wrapper exit categories in [Command reference](command-reference.md) to distinguish missing credentials (`11`), required interaction (`14`), policy refusal (`15`), and vendor incompatibility (`16`). A started vendor CLI returns its own exit code.

Run these checks during image qualification:

```bash
ctxlane --non-interactive doctor
ctxlane --non-interactive credential check --all
```

`doctor` failing because an unused provider binary is absent can be narrowed with `--provider`. Do not print `env`, vendor state, or config indiscriminately when diagnosing a credential job.

## Rotation and revocation

Supported local `logout` is cleanup, not a remote revocation guarantee. Disable or revoke WIF sources at the upstream identity provider. Revoke or rotate static credentials through the vendor when:

- a token may have appeared in logs or artifacts;
- a runner or repository is compromised;
- a user changes role or leaves;
- an access policy or workspace assignment changes;
- the configured identity source expires.

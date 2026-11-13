# Requester authentication and migration

HTTP and VSOCK require a requester token by default, before command allocation,
approval or execution. Missing/empty/malformed daemon credentials fail startup; the
plugin validates its managed credential at call time. Missing
or incorrect wire credentials fail closed. No token is generated automatically.
This intentionally breaks older unauthenticated callers. Upgrade the separate
plugin and daemon together, provision the same secret at both ends, and then
start them; do not rely on a missing configuration selecting insecure defaults.

## Explicit operator provisioning

On the trusted host, create a private parent directory, then explicitly run:

```sh
hostd create-token /absolute/private/directory/requester.token
```

This uses Python `secrets.token_urlsafe(32)` (32 random bytes), creates a new 0600
file, prints no token and refuses to overwrite an existing file or symlink.
It does not start the daemon or modify configuration. Provision a copy to the
client's Hermes-managed secrets through an operator-controlled secure channel
outside the agent's conversation, Git and tool results. The client must be able to read its own
requester credential: it is not an operator-approval secret or protection from a
compromised requester. Never copy ntfy operator/admin credentials to the client.
Keep parent directories trusted/private; same-UID/root processes can read tokens.
No automatic production provisioning, rotation, deployment or phone setup occurs.

Daemon configuration (nonsecret path only, for either transport):

```yaml
transport:
  type: vsock
  port: 9999
  auth_token_file: /absolute/private/directory/requester.token
```

The file must be a regular file owned by the daemon UID, with no group/other
permissions. Leaf symlinks, oversized/non-ASCII contents and failed reads are
rejected. One final LF is permitted. Tokens are 1..256 ASCII bearer characters
(letters/digits and `._~+/-`, with optional trailing `=`); short existing tokens
remain compatible but are not recommended. Use the generator for fresh secrets.
An explicit file takes precedence over the environment. Without a file, use
`HOSTD_AUTH_TOKEN` from the daemon process's secure environment, or select its
name with `transport.auth_token_env`. Existing explicit `transport.auth_token`
is retained for programmatic/private-config compatibility, never a public
example; file and inline sources together are rejected. An invalid selected
source never falls back to another source or insecure mode.

## Plugin rc2 migration

**Known break:** rc2 removes plugin credential-file sourcing, the bundled
`read_token_file` API and the `http_auth_token` factory alias. The daemon is
unchanged: its private file/environment configuration above remains supported.

For an existing token-file deployment, the operator must:

1. Securely provision the **same existing requester token** as `HOSTD_AUTH_TOKEN`
   in the selected Hermes profile using Hermes's managed secrets interface.
   Import/enter it outside chat, Git, command arguments and tool output. Do not
   print or rotate it merely to migrate the client. Never import ntfy approver
   credentials. Hermes, not this plugin, owns storage and profile resolution.
2. Remove `auth_token_file` entirely from both the profile's flat
   `hostd-client.yaml` and `plugins.entries.hostd-client.settings` (including a
   legacy `config` subtree if used). Unset `HOSTD_AUTH_TOKEN_FILE` in the launcher.
   Empty selectors are still selectors. **Any remaining selector is rejected,
   even with a valid managed token or explicit insecure mode.** Their targets
   are never opened, resolved or validated. The error names the removed setting
   and the managed-secret replacement, never the path or its contents.
3. Keep profile-owned transport, port, URL and response-limit settings unchanged.
   If transport values came from `HOSTD_TRANSPORT`, `HOSTD_VSOCK_PORT` or
   `HOSTD_HTTP_URL`, move them to `transport`, `vsock_port` or `http_url` in the
   profile's plugin settings or flat `hostd-client.yaml`; those environment
   overrides are now ignored, even when invalid. Remove the obsolete launcher
   variables. Deploy/reload
   the reviewed rc2 plugin separately, ensure the active profile has the secret,
   and perform an attended harmless authenticated request. Keep the daemon's
   existing private token configuration; no daemon upgrade or secret rotation is
   required for this client-only migration.

At each call the plugin lazily imports `get_secret` from `agent.secret_scope`
and requests `get_secret('HOSTD_AUTH_TOKEN')`. There is no plugin-owned raw
process-env, `.env`, token-file or credential-store fallback, and registration
never captures a secret. Hermes may resolve single-profile process credentials
as part of its own API contract; routed profiles use Hermes's scoped resolution,
not another profile's process secret. Missing/empty/malformed credentials and
import/resolution errors fail closed with bounded, value-free diagnostics.
Hermes runtime APIs are required for plugin execution; standalone library callers
instead supply `auth_token=` explicitly to `VsockClient`, `HttpClient` or
`client_from_config`. The library reads no secret stores or environment variables.

Nonsecret precedence is the flat active-profile file resolved at call time
through `get_hermes_home`, then public
`ctx.get_config` settings, then defaults. Standalone nonsecret home lookup still
supports `$HERMES_HOME`, then `~/.hermes` only when Hermes is absent. Hermes
resolution/import failures do not select a different profile. The flat parser
accepts unquoted scalar values and exact lowercase `true`/`false`, not general
YAML. No credential is a model-facing tool field.

## Explicit insecure acknowledgment

Only a deliberate operator choice may disable requester authentication:

```yaml
transport:
  type: vsock
  insecure_no_auth: true
```

The plugin retains `insecure_no_auth: true` in its nonsecret settings/flat file
for explicit manual compatibility, but this is **not a catalog setup path**:
`requires_env: [HOSTD_AUTH_TOKEN]` truthfully declares authenticated default
availability. Hermes may mark the tool unavailable without that credential, and
supplying the credential plus insecure mode is rejected. Do not configure a dummy
secret to bypass availability checks. For an explicitly invoked plugin handler,
for direct library callers pass `insecure_no_auth=True`. Each endpoint warns
`INSECURE` and still requires the normal approval. Supplying a token and insecure
mode together is an error. This permits legacy ordinary no-auth operations, not
a fallback when a token is absent. Any reachable caller can submit approvals.
Never expose this mode publicly; loopback/VSOCK alone are not authentication.


## Independent security boundaries

Requester authentication proves token possession, not guest identity, honest server
execution or human approval. Strict result validation and redirect rejection do not
supply encryption. Use externally managed TLS or SSH and protect the proxy-to-daemon
hop as well as the public hop. The ntfy reply path remains unsigned: keeping the
request endpoint private does not prevent reply forgery by actors with notification
read and matching reply-write authority.

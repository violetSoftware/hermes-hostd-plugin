# Hermes Hostd Plugin

Version 0.1.0rc2 migrates requester credentials to Hermes-managed secrets; catalog admission is pending. The plugin registers only `run_on_host` in toolset `hostd`, using public `ctx.register_tool` APIs. The bundled transport client uses only the Python standard library; plugin credential resolution requires Hermes. hermes-hostd is a separate host-side installation.

## Installation and configuration

The manifest requests Hermes >=0.22.5; this range is not a tested compatibility matrix. Use a current Hermes installation and run the validation commands below. Keep `plugin.yaml`, `__init__.py` and the complete `client/` directory together. Once installation is separately authorized, copy this source package to the selected profile's `plugins/hostd-client/`; then use `hermes -p PROFILE plugins enable hostd-client` and `hermes -p PROFILE tools enable hostd --platform cli` (enable other platforms only deliberately). This checkpoint does not install, enable or reload anything.

The manifest declares nonsecret settings under `plugins.entries.hostd-client.settings`: `transport` (`vsock` or `http`), `vsock_port` (integer, default 9999), and `http_url` (full `/execute` URL). Configure them through Hermes's plugin settings UI or approved config CLI, not by putting credentials in URLs. Settings are captured during registration; changes require a supported plugin reload or fresh process. The required credential is `HOSTD_AUTH_TOKEN`, declared in `requires_env` and resolved lazily through Hermes's `agent.secret_scope.get_secret` at each call. Configure it through Hermes's profile-managed secrets interface, not in plugin settings, a plugin-owned file or a tool argument. The plugin never reads a credential store, `.env`, token file or raw token environment variable itself. Hermes owns source resolution and routed-profile isolation; its single-profile environment support remains Hermes behavior, not a plugin fallback. `insecure_no_auth` remains an explicit unsafe manual/library compatibility option; catalog/default availability still requires the managed credential, and a token plus insecure mode is an error. See the [rc2 migration steps](docs/requester-auth.md#plugin-rc2-migration).

Precedence, highest first:

1. `HOSTD_TRANSPORT`, `HOSTD_VSOCK_PORT`, `HOSTD_HTTP_URL` in the launching process.
2. Flat compatibility file `hostd-client.yaml` in the active Hermes home, resolved at each call through `hermes_constants.get_hermes_home()` (context-local profile override, then `HERMES_HOME`, then Hermes's platform default). Shared gateways need not change the process environment to select a profile. Standalone use without Hermes retains `$HERMES_HOME`, then `~/.hermes`. A missing selected file does not trigger discovery in another profile; a Hermes resolver/import failure does not silently select the process home.
3. Manifest-backed settings read through `ctx.get_config` at registration.
4. Built-in defaults: transport `vsock`, CID 2, port 9999; HTTP URL `http://127.0.0.1:9998/execute` when HTTP is selected. There is no automatic fallback between transports.

HTTP loopback refers to the **machine/network namespace running Hermes**, not the physical host when Hermes runs in a VM/container. Selecting `http` needs no URL override if a local daemon already listens at the fallback endpoint. Otherwise explicitly configure the daemon endpoint, or establish an external SSH local forward and configure the URL to match its local listening port. The plugin does not establish tunnels automatically. The documented SSH example uses local port **19998**, so its URL is `http://127.0.0.1:19998/execute`, not the fallback port 9998.

HTTP command requests reject all 3xx responses, including same-origin redirects
and responses without Location. Configure the actual `/execute` endpoint; the
client never sends the request, bearer token or body to a redirect destination.
The error reports status only, not Location or the redirect response body.
Timeouts and urllib's normal proxy/TLS handling are unchanged. See [required requester authentication and migration](docs/requester-auth.md)
for Hermes-managed credential sourcing on both transports. See [response validation](docs/responses.md)
for strict types, exact request correlation, preserved log/additive metadata and
the configurable finite `max_response_bytes` ceiling (default 1 MiB).

The legacy parser supports only unquoted flat `key: value` lines and whole-line comments, **not general YAML**. Do not use nested mappings, quoted values or inline comments. [VSOCK](examples/hostd-client-vsock.yaml) and [HTTP-over-SSH](examples/hostd-client-http-ssh.yaml) examples contain no secrets.

## Daemon setup is separate

See [daemon setup](docs/daemon-setup.md) for terminal approval, externally managed HTTP-over-SSH, and VSOCK. This plugin neither installs nor starts the daemon, SSH, a reverse proxy or a background service. It does not manage SSH keys. Both transports forward the call-time Hermes-managed requester credential; see [provisioning and migration](docs/requester-auth.md). Never put secret values in plugin settings, URLs or examples.

## Intentional breaking removal

`mount_host_folder`, `unmount_host_folder` and the public
`client.mount_helper` module (including `mount_folder` / `unmount_folder`) have
been removed. There is no callable compatibility alias, replacement mount API,
host helper, ownership ledger or managed mount-safety guarantee.
Existing mounts and devices are untouched: this source change performs no
automatic unmount, migration, production setting change, installation or reload.
Callers must stop using the removed APIs; existing installed copies do not change
until a separately authorized deployment.

Broad writable mounting remains intentionally available through ordinary
requester-authenticated, human-approved `run_on_host` commands. If such an
operation is separately authorized, specify the VM and device identity explicitly,
for example argv:

```json
["incus", "config", "device", "add", "example-vm", "explicit-data-device", "disk", "source=/srv/example-data", "path=/mnt/example-data"]
```

Removal uses the explicitly selected device, not a path-derived name:

```json
["incus", "config", "device", "remove", "example-vm", "explicit-data-device"]
```

These are documentation examples, not executed commands. Confirm the current
configuration and intended target before requesting approval; ordinary Incus
commands do not provide helper ownership checks or race-proof compare-and-remove.
Do not infer ownership of preexisting devices or automatically remove them.
Requester authentication is distinct from human approval; the existing ntfy
approver-authentication limitation below remains.

## Risk disclosures

`run_on_host` accepts optional boolean `persistent_intent` (default false).
True declares that the caller intentionally wants a long-running process to
remain running. It is approval metadata only: it does not change `timeout`
(including explicit 0), cancellation/cleanup or authority; it does not detach,
create a service-manager job or provide background lifecycle management. The call
still waits for execution. Nonboolean values are rejected before client creation.
A matching updated daemon must validate, display and digest-bind this field;
older daemons may ignore unknown fields. Deploy separately with matching daemon
support. The matching daemon performs ordinary owned-process-group timeout/disconnect cleanup. Deliberate process-group escapes, delegated jobs and hostile same-user interference are outside that boundary; the marker grants no cleanup exception or lifetime guarantee.

- The tool sends command argv, descriptions and request IDs to the configured host daemon and returns host stdout/stderr. Responses may contain sensitive data and reach the agent/model provider. The plugin reads its profile-local compatibility file; it does not infer a VM identity from the hostname.
- Host commands execute with the **daemon account's privileges**. Ordinary approved Incus argv can still request persistent writable disk-device changes and expose host files inside a guest. The command tool is not a sandbox or a constrained filesystem API.
- Host execution uses the daemon's approval channel, not Hermes's built-in terminal approval flow. Never use it to evade a denied Hermes command. Terminal approval on the host is the first-release baseline; no live approval path was exercised in this checkpoint. Unattended use must retain finite approval deadlines; command `timeout: 0` preserves the existing indefinite wait behavior and is unsuitable for unattended checks.
- **Existing ntfy decisions are unsigned and do not authenticate the human approver.** A party able to publish a matching request ID and approval decision to the response channel can forge approval. Topic obscurity, HTTP/SSH reachability restrictions and ntfy publishing credentials do not prove human intent against a compromised requester. Do not advertise ntfy as a strong authorization boundary. Optional ntfy mode also sends command metadata to a third-party/self-hosted service. It is not configured or tested here.
- The plugin reads its requester credential into transport memory, never model-facing arguments; it launches no local shell commands or background processes, and has no updater or telemetry. The separately installed daemon does execute commands and log command metadata. External SSH/proxy processes remain the operator's responsibility.

`capabilities: []` means no Hermes override/LLM/platform-action grants are requested. It **does not mean no remote-command risk**: current Hermes capability IDs are specific gated surfaces, not generic network/filesystem/shell permissions. Registration declarations are `provides_tools`/`provides_hooks`, and the catalog entry's capability block is a separate structure.

## Local verification

From any checkout:

```sh
python -B -m unittest discover -s tests -v
```

The harness requires the installed Hermes secret-scope API (it is not a standalone stdlib-only plugin runtime). It honors `TMPDIR`, falling back to `tempfile.gettempdir()`. It relocates source, starts `python -I -B` with an empty fixture `HERMES_HOME`, blocks legacy checkout/config access and global client imports, and checks unchanged `sys.path`. It exercises registration, configuration precedence, missing-client errors, removal of mount convenience APIs, ordinary inert Incus argv and a real HTTP POST to an inert `127.0.0.1` fixture. The fixture never executes commands or requests approval. The tests require an installed Hermes runtime at `/usr/local/lib/hermes-agent` (override with `HOSTD_TEST_HERMES_SOURCE`) and that runtime's Python dependencies. It uses the real public `PluginContext` and `registry.get_definitions` in a fresh process with disposable `HOME`/`HERMES_HOME`, restricts network to inert loopback and denies subprocess activity and out-of-fixture writes, and checks the sole supported tool, absence of removed registrations and manifest promises, argument types, required fields and exactly one provider wrapper. Unrelated bundled model-provider discovery is excluded from that probe.

Catalog validation normally uses `hermes plugins validate /path/to/checkout --json`. Run it only in a separately authorized, disposable environment: the full Hermes launcher can perform startup maintenance and load environment/configuration outside the checkout. Do not add `--install-deps` without separate permission. The stdlib suite above does not exercise the catalog validator or full launcher. Passing local checks is not live daemon, VSOCK, SSH, phone approval or full clean-install acceptance.

MIT licensed by Violet Software. Source repository: https://github.com/violetSoftware/hermes-hostd-plugin. Catalog admission and deployment remain separate steps. Do not commit runtime configuration, credentials, private topics, logs or environments.

## Candidate status and deployment boundary

This is **0.1.0rc2**, a breaking credential-source migration from rc1.
Existing token-file deployments must provision the Hermes-managed secret and remove
all legacy client file selectors before calling the upgraded plugin.
Copyright 2026 Violet Software. Distributed under the [MIT License](LICENSE).
Source: https://github.com/violetSoftware/hermes-hostd-plugin. Installation and
live acceptance are separate from source tests.

Linux is the implementation target (Linux process groups/subreaper, flock and
PTY behavior). Python metadata permits >=3.10; candidate checks use Python 3.14.9
and aiohttp 3.14.5, not a full interpreter/dependency/platform matrix. No native
host/hypervisor AF_VSOCK, phone, broker ACL, SSH or production deployment is
established by synthetic loopback/socket/PTY tests. Separate exact-artifact review
is required before this local checkpoint is accepted.

Keep deployed executable, dependencies, configuration and approval credentials
outside directly requester-writable development shares. Run with only the account
authority you intend to grant through approval; approved arbitrary commands can
change files, mount writable host data, detach work or launch external services.
There is no command sandbox or overall CPU/memory/job quota. Ordinary process-group
cleanup is not deliberate-escape containment and cannot undo completed effects.

Both HTTP and VSOCK require requester credentials unless explicitly configured
`insecure_no_auth: true`. That opt-out warns and removes requester authentication;
missing credentials never select it implicitly. Tokens authenticate possession,
not the human approver. HTTP needs external TLS/reverse proxy or a secure tunnel
when crossing an untrusted network; protect **every hop**, including any
proxy-to-daemon link, and prevent direct bypass. VSOCK is not IP and supplies no
native encryption.

ntfy decisions are unsigned. Reading an active notification plus publishing a
matching reply permits forged approval. Exclusive requester access alone does
not protect that reply path. Broker/notification/reply access isolation is the
operator's responsibility; random topics and daemon broker credentials do not
prove human intent. Concurrency/receive bounds do not rate-limit notification spam.

Command descriptions/argv reach approval readers and possibly a broker. Output
persists in private bounded logs and may reach the requester/model provider.
Escaping is not redaction: avoid secrets in argv/descriptions, keep log directories
private, and review commands for intentional secret output. Requester transport
tokens are not command fields and must not enter approval payloads or diagnostics.

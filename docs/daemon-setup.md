# Separate daemon setup (operator-run, not performed by this checkpoint)

Install a reviewed hermes-hostd source and its declared dependencies on the **host**, separately from this plugin. The daemon's Python YAML loader needs PyYAML for the examples below (JSON is its documented fallback). Keep daemon configuration and any credentials in host-owned, guest/agent-inaccessible locations. Never copy an existing production config into this repository. Run the daemon with the least privileges required; Incus administration can confer broad host authority.

## Terminal approval baseline

Choose one nonsecret example and adapt it deliberately on the host:

- [HTTP bound to host loopback](../examples/daemon-cli-http.yaml)
- [VSOCK](../examples/daemon-cli-vsock.yaml)

Both set `approval.type: cli`, a 30-second approval deadline, and an executable allowlist containing only `/usr/bin/printf` for an attended harmless initial probe. The allowlist compares only `argv[0]`, not arguments or intent; it is not a comprehensive security policy. An absent or empty daemon allowlist allows every executable. Do not add shells/interpreters or blanket Incus access merely to make a test pass. Ordinary `run_on_host` Incus commands need separately authorized `incus` access and are not admitted by these minimal examples. There are no specialised mount/unmount tools or bundled mount helper.

In an operator-controlled host terminal, after installing and reviewing the daemon:

```sh
python /path/to/reviewed/hermes-hostd/hostd.py --config /path/to/host-owned/daemon-cli-http.yaml
```

Use an explicit existing config path: daemon source falls back to other config locations when the supplied path is missing. The CLI approver uses `/dev/tty`; keep it attached to the operator's terminal. Without a controlling terminal it denies requests. Finite approval timeout is intended to deny unanswered requests; this checkpoint did not test daemon terminal behavior or concurrency. Do not convert this baseline to unattended systemd operation or indefinite approval waits.

## Externally managed HTTP-over-SSH

The default transport remains VSOCK. When HTTP is selected, the fallback URL is `http://127.0.0.1:9998/execute`. Loopback refers to the machine/network namespace running Hermes, **not the physical host** when Hermes runs in a VM/container. A local daemon already listening at that endpoint needs no URL override. Otherwise explicitly configure the daemon endpoint, or establish an external SSH local forward and configure the URL to match its local listening port. The plugin never establishes tunnels automatically.

For HTTP-over-SSH, use the loopback HTTP daemon example and establish the forward from the guest/client machine separately:

```sh
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:19998:127.0.0.1:9998 operator@host.example
```

`host.example` is a placeholder. The operator authenticates SSH and verifies the host key outside the plugin. The command stays foregrounded; the plugin does not create, keep alive or restart it. Configure the plugin endpoint as `http://127.0.0.1:19998/execute`, using the supplied client example or manifest-backed settings. This example deliberately uses local listening port **19998**, distinct from fallback port **9998**; the forward's remote destination is the daemon's host-loopback port **9998**.

Both examples require a separately provisioned requester token. Configure the private file path in both daemon and client, or use protected process environment sources. Missing credentials fail closed; an insecure mode is available only through explicit acknowledgment. Follow [requester authentication](requester-auth.md) for generation, provisioning, migration and the plaintext hops remaining around SSH/TLS. No tunnel, listener, host request or approval was created here.

## VSOCK

Use the VSOCK daemon example and client example together. The client connects to host CID 2, port 9999; the daemon port must match. Both kernels/VM configuration must provide AF_VSOCK and guest-host routing. VSOCK reachability does not authenticate a human approver or restrict a compromised guest, and other guests with access may be able to request commands. Keep terminal approval and restrictive host policy. This checkpoint has not exercised VSOCK and makes no deployment-readiness claim.

## Attended acceptance still required

After separate deployment permission, an operator should submit a finite `run_on_host` request with argv `["/usr/bin/printf", "hostd attended probe\\n"]`, review/deny once, then approve once, and verify the daemon result's request ID, `approved`, `exit_code`, stdout and error. These are future acceptance checks, not results reported here. Check `approved == true` **and** `exit_code == 0`; approval alone is not success. Any future Incus device exercise requires separate authorization for a disposable guest/folder and an explicit device identity; this checkpoint neither inspects nor changes existing devices.

Do not replace terminal approval with ntfy for a security claim: existing response decisions are unsigned and forgeable by a publisher with response-channel access. SSH transport and a working phone notification do not fix that decision-authentication gap.

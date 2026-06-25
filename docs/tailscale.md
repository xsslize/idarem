# Remote access over Tailscale

This guide sets up access to `idarem` from anywhere — including a phone that
already runs another VPN — using **Tailscale Funnel**, which publishes the plugin's
web UI over public HTTPS. No Tailscale client is needed on the viewing device.

There are two ways to reach the server with Tailscale. Pick by your situation:

| Situation | Use | Client on the viewing device? |
| --- | --- | --- |
| The laptop/phone *can* run Tailscale | **Serve / tailnet IP** (private) | Yes — joins your tailnet |
| The phone already runs another VPN (only one VPN allowed at a time) | **Funnel** (public HTTPS) | **No** — just a browser |

Most of this guide is about **Funnel**, since that's the case that needs setup.
If your viewing device can join the tailnet, skip to [Private access](#private-access-no-funnel).

> Tailscale is just one option. The plugin only serves plain HTTP on a port, so it
> works behind **anything** that can reach that port: a LAN connection, any tunnel
> (Cloudflare Tunnel, ngrok, `frp`/`rathole`), a reverse proxy (Caddy/nginx) on your
> own VPS, a corporate VPN, an SSH port-forward, or nothing at all for purely local
> use. Pick whatever fits your network — the client and token work the same way.

---

## Prerequisites

- [Tailscale](https://tailscale.com/) installed and logged in **on the machine running IDA** (the "home PC").
- `idarem` installed and serving: build the web client and run the plugin so
  `http://localhost:8765` shows the UI (see the main [README](../README.md#quick-install-windows-recommended)).

Verify locally first: open `http://localhost:8765` on the IDA machine. You should
see the connection page. If not, fix that before exposing anything.

---

## Funnel: public HTTPS access

### 1. Enable HTTPS + MagicDNS

In the Tailscale admin console → **DNS**:

- enable **MagicDNS**, and
- enable **HTTPS Certificates**.

Funnel serves over TLS and needs both.

### 2. Allow Funnel in the ACL

Admin console → **Access controls**. Add a top-level `nodeAttrs` block granting the
`funnel` attribute (it sits alongside `grants` and `ssh`, not inside them):

```jsonc
{
  "grants": [
    { "src": ["*"], "dst": ["*"], "ip": ["*"] },
  ],

  // Allow this user's devices to publish services with Funnel.
  "nodeAttrs": [
    {
      "target": ["autogroup:member"],
      "attr":   ["funnel"],
    },
  ],

  "ssh": [
    {
      "action": "check",
      "src":    ["autogroup:member"],
      "dst":    ["autogroup:self"],
      "users":  ["autogroup:nonroot", "root"],
    },
  ],
}
```

- `target: ["autogroup:member"]` — your own (non-tagged) devices, which is what the home PC is.
- `attr: ["funnel"]` — the permission itself.

Save.

### 3. Set a real auth token

Funnel makes the server reachable by **anyone on the internet who has the URL**, so a
token is mandatory. In `plugin/idarem.py`, set `AUTH_TOKEN` to a strong secret:

```sh
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Paste the result into `AUTH_TOKEN` and reload the plugin. (The repo ships a
placeholder on purpose — never serve with it.) If you also enable write-back
(`ALLOW_WRITE = True`, the default), remember the token now also guards renames and
comments to your database — set `ALLOW_WRITE = False` if you want remote viewing only.

### 4. Start the Funnel

On the IDA machine, with the plugin running and serving on 8765:

```sh
tailscale funnel 8765
```

It prints something like:

```
Available on the internet:
https://desktop-abcd123.tailXXXX.ts.net/
|-- proxy http://127.0.0.1:8765
```

That `https://….ts.net/` is your public URL. Funnel publishes on a standard public
port (443) and proxies it to your local 8765 automatically.

Useful variants:

```sh
tailscale funnel --bg 8765     # run in the background
tailscale funnel status        # show what's published
tailscale funnel reset         # stop publishing
```

Funnel only runs while that command (or the `--bg` service) is active.

### 5. Connect from the phone / laptop

Open the `https://….ts.net/` URL in any browser — **your other VPN can stay on**, no
Tailscale client needed. The connection page prefills the host with that URL, so you
just enter the **token** and press **Connect**.

---

## Private access (no Funnel)

If the viewing device can run Tailscale, you don't need Funnel at all — it's more
private (nothing is published to the internet):

1. Install Tailscale on both machines and log into the same tailnet.
2. Find the home PC's tailnet IP (`100.x.y.z`) — `tailscale ip -4`, or the admin console.
3. On the other device, open `http://100.x.y.z:8765` and connect.

This works over the internet, not just the LAN, because Tailscale builds a direct
encrypted tunnel between the two devices. A token is still recommended.

---

## Troubleshooting

**`502 Bad Gateway` at the Funnel URL.** Funnel reached Tailscale, but nothing
answered on `127.0.0.1:8765`. The plugin server isn't running:

- Make sure **IDA is open** with a database and the plugin is started
  (`Ctrl-Alt-R`; the Output window shows `[idarem] serving on http://0.0.0.0:8765`).
- Confirm `http://localhost:8765` works locally on the IDA machine.
- Funnel and the plugin are **two separate processes** — both must be running at the
  same time. Closing IDA brings the 502 back.

**The page loads but shows a plain "API server is running" help page.** The plugin
didn't find the built web client. Run it from the repo (so it auto-detects `web/dist`)
or set `WEB_ROOT` / `IDAREM_WEB_ROOT` — see the main README.

**`401 unauthorized`.** The token in the connection page doesn't match `AUTH_TOKEN`
in the plugin. They must be identical, and the plugin must have been reloaded after
changing it.

---

## Security checklist

- ✅ A strong, unique `AUTH_TOKEN` (never the repo placeholder) whenever the server
  is reachable beyond `localhost`.
- ✅ `ALLOW_WRITE = False` if you only want to read the database remotely.
- ✅ Prefer **private** tailnet access (Serve / tailnet IP) over **Funnel** when the
  viewing device can run Tailscale — Funnel is public to the whole internet, gated
  only by your token.
- ✅ Stop the Funnel (`tailscale funnel reset`) when you're done.

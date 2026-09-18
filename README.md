# SENTRY

A privacy-first Windows and home-network security app. It checks your PC and
your network and explains, in plain language, what needs fixing.

Everything it learns stays on this machine. There is no account, no server and
no telemetry.

---

## The rule this codebase is built around

**A check that did not run is never shown as a check that passed.**

That sounds obvious and is surprisingly hard. Most of the design follows from it:

- The backend's core type is `Known<T>` — a fact is either established, or it is
  one of `NotScanned`, `PermissionRequired`, `Unsupported` or `Unavailable`,
  each carrying a reason. A collector that fails has no way to return "fine".
- Every finding carries the evidence that produced it: the registry value, the
  WMI class, the CPE match, the port and process. No finding is prose.
- The score travels with its coverage. A 97 over four working checks is not a
  97, and the dashboard says which areas did not report.
- Where something genuinely cannot be determined from inside the network — most
  importantly whether your router is reachable from the internet — it says so
  rather than guessing.

## What it checks

| Area | How |
|---|---|
| Defender status | WMI `MSFT_MpComputerStatus` |
| Defender configuration | WMI `MSFT_MpPreference` — exclusions, archive/USB/script scanning, PUA |
| Malware history | WMI `MSFT_MpThreatDetection` — including threats Defender failed to remove |
| Firewall | COM `INetFwPolicy2`, per profile, active profile distinguished |
| Windows Update | WUA COM (`wuapi.dll`), cached metadata only |
| System hardening | Registry — SMBv1, UAC, RDP, AutoRun |
| Installed software | Registry uninstall keys, 64-bit + 32-bit + per-user |
| Vulnerabilities | NVD CVE API 2.0 + CISA KEV + FIRST EPSS, matched by CPE and version range |
| Network | `GetAdaptersAddresses`, `GetIpNetTable2`, DNS resolver analysis |
| Devices | Passive ARP cache plus an optional `SendARP` sweep, IEEE MAC vendor lookup |
| Open ports | `GetExtendedTcpTable` — loopback and network-reachable kept distinct |
| Router | SSDP/UPnP — make, model and port forwards from the internet |

Deliberately **not** included: a bespoke antivirus engine. Defender already
scans every file continuously with real signatures. SENTRY reports what Defender
found and whether it actually dealt with it, and can ask it to scan or update.

## Privacy

A scan makes **no network requests at all** — it reads only data already on the
machine. The only outbound traffic is an explicit, cancellable refresh of public
vulnerability data:

| Destination | What is sent |
|---|---|
| `services.nvd.nist.gov` | A product name as a search term. No version, no identifier. |
| `cisa.gov` | Nothing. The whole catalogue is downloaded. |
| `api.first.org` | Public CVE identifiers already downloaded from NIST. |
| `standards-oui.ieee.org` | Nothing. The whole registry is downloaded and searched locally, so no MAC address from your network is ever sent. |

The in-app **Privacy** page counts what is stored directly from the database file
and lists these endpoints with the date each was last contacted — so the claim is
checkable rather than merely asserted.

### One deliberate exception
CISA's CDN answers `403` to any non-browser user agent, including one that
identifies SENTRY honestly. That one feed is therefore fetched with a generic
browser user-agent string, documented at the call site in
`src-tauri/src/vulnerabilities/feeds/http.rs`. It is a bot-protection rule
blocking a file CISA publishes *for* automated use; nothing else about the
request changes and no credentials are involved.

## Building

Requires Rust (1.82+), Node 20+, and the MSVC build tools.

```bash
npm install
npm run app          # run in development
npm run app:build    # build installers
cargo test           # from src-tauri/ — 396 tests
```

Useful during development, from `src-tauri/`:

```bash
cargo run --example probe            # every collector, against this machine
cargo run --example probe scan       # the whole dashboard payload
cargo run --example sweep            # active device discovery
cargo run --example router           # UPnP / port forwards
cargo run --example fix_probe        # remediation, without changing anything
```

## Releasing

`npm run app:build` produces an MSI and an NSIS installer, plus a `.sig` for
each. Updates are verified with Minisign before installation and that check
cannot be disabled.

Signing needs the private key, which is **not** in this repository:

```bash
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.sentry-keys/sentry-updater.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
npm run app:build
```

Lose that key and no future build can be published as an update to this one.

### Not yet done: Authenticode

The installers are **not** signed with a code-signing certificate, so Windows
SmartScreen will warn on first run and users must click through. Fixing it needs
an OV or EV certificate (an EV certificate avoids the reputation-building
period). Once you have one, add to `tauri.conf.json`:

```json
"windows": { "certificateThumbprint": "...", "digestAlgorithm": "sha256",
             "timestampUrl": "http://timestamp.digicert.com" }
```

and supply it to CI as a secret.

## Layout

```
src/                     React UI
  components/            views and panels
  services/ipc.ts        the only place the UI talks to the backend
src-tauri/
  src/collectors/        privileged OS reads -> typed facts
  src/rules/             the only layer that decides if something is a problem
  src/findings/          the Finding model
  src/engine/            scan orchestration, scoring, background monitoring
  src/remediation/       the fixed list of changes SENTRY can make
  src/vulnerabilities/   feeds, CPE matching, version ranges
  src/ipc/               the privilege boundary — every command is named and typed
  migrations/            forward-only SQL
  capabilities/          Tauri's default-deny permission set
```

The IPC boundary has no generic `execute(command)`. Remediation is a fixed enum
of named verbs; nothing a feed or a model produces ever becomes something that
runs.

## Known limits

- **Background monitoring runs while the app runs.** Closing the window hides it
  to the tray and monitoring continues, but quitting stops it. There is no
  privileged Windows service, by choice: a SYSTEM service on a home machine is
  permanent attack surface a home user cannot audit.
- **Defender's exclusion list needs administrator rights to read.** Without them
  the app reports that it could not check, rather than reporting none.
- **Applying Defender policy fixes needs administrator rights.** SENTRY checks
  before attempting and explains, rather than failing with a hex code.
- **Router internals need the router's password**, which SENTRY does not ask for.
  Wi-Fi encryption, default admin passwords and firmware version are listed as
  unavailable rather than guessed.
- **Vulnerability matching is fuzzy at the edges.** Advisories that state no
  affected version range cannot be resolved either way and are reported as
  undetermined, not as vulnerabilities.

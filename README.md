# Dropbox session watchdog — Intune remediation package

Keeps the Dropbox client running for **every user** of a Windows 11 device, **however
Dropbox was installed**, and relaunches it in that user's own desktop session whenever
it exits.

Addresses one specific failure mode: Dropbox exits without warning at unpredictable
intervals and synchronisation silently stops until somebody notices and restarts it.

Deploy it with Intune Remediations, scoped to whichever device group needs it.

---

## Why this is not just "detect Dropbox, start Dropbox"

The obvious remediation pair — detect that `Dropbox.exe` is missing, then `Start-Process`
it — does not work, for four reasons:

| Problem | Consequence |
|---|---|
| Intune remediations run as **SYSTEM** by default | `$env:LOCALAPPDATA` resolves to SYSTEM's profile, so a per-user install at `%LOCALAPPDATA%\Dropbox\bin\Dropbox.exe` is invisible |
| SYSTEM has no desktop | `Start-Process` launches Dropbox into **session 0**, where it has no tray icon, no UI and no working sync |
| Running "as the logged-on user" fixes only one user | On a shared or multi-session device, the other users stay broken |
| Intune's fastest schedule is **hourly** | Up to 60 minutes of dead sync per crash |

So Intune is used for what it is good at — guaranteed, policy-driven presence on every
device in the group — and the actual monitoring is done by a small watchdog that runs
**inside each interactive user session**.

```
Intune (hourly, SYSTEM)                 Device
┌───────────────────────┐
│ Detect-DropboxWatchdog│──exit 1──┐
└───────────────────────┘          │    C:\ProgramData\DropboxWatchdog\bin\
┌───────────────────────┐          ├──▶   DropboxWatchdog.ps1   (hash-verified)
│Remediate-DropboxWatch.│──────────┘      version.json
└───────────────────────┘                 
                                    Task Scheduler: \DropboxWatchdog\DropboxWatchdog
                                      principal = BUILTIN\Users  (group, not a user)
                                      triggers  = at logon (any user) + every 30 min
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                           ▼
        session 1 (alice)           session 2 (bob)            session N (future user)
        watchdog loop, 45s          watchdog loop, 45s          watchdog loop, 45s
              │                           │                           │
              └── relaunches alice's Dropbox in alice's session, etc. ┘
```

Because the scheduled task's principal is the **BUILTIN\Users group** rather than a named
account, Task Scheduler instantiates it inside the session of whoever signs in — including
users who have never logged on to the device before. No stored credentials, no per-user
deployment, no session-0 launches.

---

## Why SYSTEM, even on single-user devices

"Run using the logged-on credentials = Yes" is the obvious alternative, and on a device
with one primary user the multi-user argument mostly evaporates. It is still the wrong
choice, for reasons that have nothing to do with how many people use the machine:

| | SYSTEM + installed watchdog | User-context remediation |
|---|---|---|
| Worst-case downtime | ~45s (watchdog poll) | ~60 min (Intune's floor) |
| Runs when nobody is signed in | Installs normally | Skipped entirely |
| Application event log source | Created (admin-only operation) | **Impossible** — file logs only |
| Script tamper resistance | Admin-only ACL | User can edit what runs at their own logon |
| Allow-listable under AppLocker/WDAC | Yes — fixed, admin-only path | No — user-writable path can't be trusted |
| Survives ConstrainedLanguage | Yes — verified in a real constrained runspace | Same code, but nothing protects it |
| Device reassigned to a new user | Covered automatically | Re-runs, but nothing persists |

The decisive one is the first row, and it is unchanged by user count: Intune cannot check
more often than hourly, so **any** design that relies on the Intune schedule to catch the
crash leaves sync dead for up to an hour. Once you accept that something has to live on
the device and poll, the only question is who installs it — and a standard user cannot
create an event log source or protect the script from itself.

The event log row is worth dwelling on. The real goal is not just restarting Dropbox, it
is finding out *why* it keeps dying. Event IDs 2001/3000/3001 with the captured crash
evidence are collectable centrally; a text file in one user's profile is not.

**Single-user does not buy simplification.** The only multi-user-specific parts are the
group principal (one line, and it is *simpler* than naming a user), `MultipleInstances
Parallel`, and the session mutex. Session-ID filtering stays either way — it is what stops
a session-0 or orphaned process being mistaken for a healthy client. There is nothing to
remove.

### PowerShell language mode (AppLocker / WDAC)

If AppLocker script enforcement or WDAC applies to these devices, a standard user's
PowerShell runs in `ConstrainedLanguage`, where `New-Object` on non-core types,
`[pscustomobject]` casts and static .NET calls all fail. The watchdog runs as the user,
so this is the context that matters — and it is not something you can always check
before deploying.

**The watchdog is written to run constrained.** It uses hashtables rather than
`[pscustomobject]`, plain arrays rather than generic lists, a PID lock file rather than a
named mutex, and the `Write-EventLog` *cmdlet* rather than `[System.Diagnostics.EventLog]`
— cmdlets remain available under ConstrainedLanguage, static .NET calls do not.

This is verified, not asserted. `tests/ConstrainedLanguage.Tests.ps1` sets a child
runspace to `ConstrainedLanguage` and runs the real payload inside it — 22 checks
covering config parsing, discovery, state round-tripping, the session lock, and a full
Dropbox restart cycle including crash-loop throttling.

```zsh
zsh scripts/test.sh tests/ConstrainedLanguage.Tests.ps1
```

**You do not need to check a device up front.** The watchdog records its language mode in
its heartbeat, and detection surfaces it in the Intune portal:

```
COMPLIANT: Dropbox watchdog 1.0.0 installed, task scoped to all users, heartbeats fresh.
 NOTE: 1 session(s) running under restricted PowerShell (S-1-5-21-…=ConstrainedLanguage);
 the watchdog supports this, but script enforcement is active on this device.
```

That is a **note, not a fault** — the device stays compliant, because the watchdog works.

#### What genuinely cannot run constrained

The **remediation** script itself. It must base64-decode and gunzip the embedded payload,
which needs `[System.Convert]` and `[System.IO.Compression]`. There is no cmdlet-only
equivalent, so it refuses to half-install and says why:

```
FAILED: PowerShell is running in ConstrainedLanguage, not FullLanguage, in the SYSTEM
context. … The Intune Management Extension script directory and
"C:\ProgramData\DropboxWatchdog\bin" both need allow-listing.
```

In practice this only happens under WDAC, which constrains SYSTEM too. Under AppLocker
alone, administrators and SYSTEM are exempt, so the installer runs normally and only the
user session is constrained — which the watchdog handles. If you do hit it, allow-list the
Intune Management Extension script directory; `C:\ProgramData\DropboxWatchdog\bin` is
admin-write-only precisely so it is safe to allow-list too.

## What the watchdog does

Every 45 seconds, inside each user session:

1. **Finds Dropbox for this user**, in priority order:
   `HKCU\...\Run` value (authoritative — it is how Dropbox starts itself) → `HKLM\...\Run`
   → `HKCU/HKLM\Software\Dropbox\InstallPath` → uninstall keys (incl. `WOW6432Node`)
   → `%LOCALAPPDATA%\Dropbox\bin` → `%LOCALAPPDATA%\Dropbox\Client`
   → `%ProgramFiles(x86)%\Dropbox\Client` → `%ProgramFiles%\Dropbox\Client`
   → Microsoft Store package (launched via `shell:AppsFolder`).
   The first candidate that actually exists on disk wins, so a stale `Run` entry pointing
   at a removed install cannot win.
2. **Checks whether Dropbox is running in *this* session** (`SessionId` match). Another
   user's Dropbox is never counted, and never touched.
3. If it is gone, and none of the stand-down conditions apply, **relaunches it** with the
   arguments Dropbox registered for itself (`/systemstartup` by default), waits 20 s, and
   confirms it survived.
4. **Logs** to `%LOCALAPPDATA%\DropboxWatchdog\watchdog.log` and to the Windows
   **Application** event log (source `DropboxWatchdog`), including the most recent
   `Application Error` / `Application Hang` / WER record naming `Dropbox.exe` — so you get
   root-cause evidence, not just "it died again".

### Stand-down conditions (the "gracefully" part)

The watchdog does **not** relaunch when:

| Condition | Why |
|---|---|
| Session 0 | Dropbox cannot work there |
| `explorer.exe` is not running in the session | User is logging off, or the shell crashed — launching would block logoff |
| `DropboxUpdate.exe` / an installer is running in the session | Don't race Dropbox's own updater |
| A pause marker exists | Escape hatch for support (see below) |
| 6 restarts already happened in the last rolling hour | Crash-loop protection |

Backoff between consecutive failed restarts walks `5s → 15s → 60s → 5m → 15m`.

When the hourly budget is exhausted the watchdog writes **event ID 3001** and stops
restarting until the rolling window clears — deliberately, so a genuinely broken client
is not respawned in a tight loop. Alert on 3001: it means that device needs a human.

### Event IDs (Application log, source `DropboxWatchdog`)

| ID | Meaning |
|---|---|
| 1000 / 1001 | Watchdog loop started / stopped in a session |
| 2000 | Dropbox not installed for this user |
| 2001 | Dropbox found dead, relaunch attempted (includes crash evidence) |
| 2002 | Relaunch succeeded and survived the settle window |
| 3000 | Relaunch failed, or Dropbox exited again immediately |
| 3001 | **Crash loop — restarts suppressed, investigate this device** |
| 4000 | Watchdog internal error |

---

## Repository layout

```
src/
  payload/DropboxWatchdog.ps1              the per-session watchdog (the real logic)
  common/SharedContract.ps1                single source of truth: paths, task shape, version
  templates/*.tmpl                         detection / remediation / removal / uninstall
scripts/
  build.sh                                 src/ -> build/  (embeds + hashes the payload)
  test.sh                                  runs the suite in Docker
  intune-login.sh                          sign the Intune account into its own az profile
  deploy-intune.sh                         create/update the remediation, assign to a group
  update-intune.sh                         push a new payload version
  teardown-intune.sh                       deploy the removal remediation, then delete
  lib/graph.sh                             Microsoft Graph auth + request helpers
tests/                                     Pester 5 suite + Windows-cmdlet shims
  clm/                                     runs the payload in a real constrained runspace
build/                                     generated - what you upload to Intune
Dockerfile, docker-compose.yml             containerised test runner
```

`build.sh` gzip+base64-encodes the payload into the remediation script and stamps its
SHA-256 and version into the shared contract, so **detection, remediation, removal and
uninstall can never disagree** about what "installed and current" means. Tests assert the
contract block is byte-identical in all four generated scripts, that the embedded payload
decompresses byte-for-byte back to `src/payload/DropboxWatchdog.ps1`, and that what the
remediation writes is exactly what the detection accepts.

---

## Build and test

```zsh
zsh scripts/build.sh          # -> build/*.ps1 + build/manifest.json
zsh scripts/test.sh           # full suite in Docker (the same image CI uses)
zsh scripts/test.sh --rebuild # force a fresh image
zsh scripts/test.sh --local   # if you have pwsh 7 + Pester 5 installed
```

The scripts target Windows PowerShell 5.1, which cannot run in a Linux container, so the
suite mocks the Windows-only surface — Task Scheduler, WMI, the registry, the event log,
process enumeration — behind thin wrapper functions and exercises the real decision logic.
Filesystem behaviour runs against a real temp sandbox rather than a mocked `Test-Path`.

Two guards make sure silence is never mistaken for success:

* every unmocked Windows shim **throws**, so a forgotten mock fails the test instead of
  quietly passing; and
* the runner fails the build if fewer than 70 tests actually executed.

Static analysis (PSScriptAnalyzer), a parse check, a Windows PowerShell 5.1 compatibility
check (no ternary, no `??`, no `&&`/`||` chains — verified against the AST, not by regex)
and `zsh -n` on every shell script all run as part of the suite.

---

## Signing in when Intune lives on a second account

If the account you normally use with `az` is not the one holding your Intune role, do
**not** switch your default Azure CLI session back and forth. `az account
get-access-token` silently uses whichever account is current, so an `az account set` you
forgot is a deploy under the wrong identity.

Give the Intune account its own Azure CLI profile instead:

```zsh
zsh scripts/intune-login.sh --account intune-admin@contoso.com
```

That signs in with `--allow-no-subscriptions` (an Intune-only admin account usually has no
Azure subscription, and without this `az` treats the login as a failure) into
`~/.azure-intune`, verifies the account can actually mint a Graph token with Intune
scopes, and writes a gitignored `.dbw.env`:

```zsh
export DBW_AZURE_CONFIG_DIR="$HOME/.azure-intune"
export DBW_EXPECT_UPN="intune-admin@contoso.com"
```

From then on:

* Every `az` call the deploy scripts make runs with `AZURE_CONFIG_DIR` pointed at that
  profile. **Your everyday `az login` is never switched, clobbered or used for Intune** —
  `az account show` in your normal shell keeps reporting what it always did.
* `deploy`, `update` and `teardown` print the account they are acting as and **abort
  before sending anything** if it is not `DBW_EXPECT_UPN`.
* Both profiles stay signed in at once; there is nothing to switch.

```zsh
zsh scripts/intune-login.sh --status     # who is this profile, and can it manage Intune?
zsh scripts/intune-login.sh --logout     # drop it
```

Refresh tokens expire, so expect to re-run the login periodically; `--status` tells you
when. Add `--device-code` if the browser keeps picking your everyday account.

### If you get a 403

A successful login only means you authenticated. The Azure CLI's own client app must also
be consented for `DeviceManagementScripts.ReadWrite.All` in the tenant, and in many
tenants it is not. The scripts inspect the token's scopes and warn you *before* sending
anything.

> Remediations are governed by `DeviceManagementScripts.*`, **not**
> `DeviceManagementConfiguration.*`. The latter covers other Intune resources and will
> not get you past a 403 on `deviceHealthScripts`.

If that consent is missing — or for anything scheduled or shared — use an app registration.
It is the better answer for repeated use anyway: no dependency on a human account, no
expiry every few hours, and it is what CI needs.

```zsh
export DBW_TENANT_ID=...  DBW_CLIENT_ID=...  DBW_CLIENT_SECRET=...
unset DBW_EXPECT_UPN     # that guard is for user sign-ins
```

Give the app the **application** permission `DeviceManagementScripts.ReadWrite.All`
with admin consent (Graph app id `00000003-0000-0000-c000-000000000000`). When these three variables are set the Azure CLI is not used at all,
so your `az` session is irrelevant.

If your Intune role is **PIM-eligible** rather than permanently assigned, activate it
before deploying — the token is minted at deploy time, and an unactivated role produces
the same 403 that the scope warning will not catch.

## Prerequisites

Confirm these before deploying, in this order. The first is a tenant toggle that is
**off by default** and blocks Remediations entirely.

### 1. Tenant licence attestation (off by default)

**Tenant administration** -> **Connectors and tokens** -> **Windows data** ->
*I confirm that my tenant owns one of these licenses* -> **On**.

Microsoft lists Remediations as a feature requiring this attestation, and it defaults to
*Off*. It "confirms tenant entitlement for those features; it does not validate or assign
licenses to individual devices". An **Intune Service Administrator** must set it before
Remediations is used for the first time.

If assignment fails in the portal and nothing else here is wrong, check this first.

### 2. Device-user licensing

Remediations require **the users of the devices** - not the administrator - to hold one of:

* Windows Enterprise E3 or E5 (included in Microsoft 365 F3, E3, E5)
* Windows Education A3 or A5 (included in Microsoft 365 A3, A5)
* Windows Virtual Desktop Access (VDA) per user

To check what a device's owner actually holds:

```zsh
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/devices/<entra-device-object-id>/registeredOwners" \
  --query "value[].userPrincipalName" -o tsv

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/users/<upn>/licenseDetails" \
  --query "value[].skuPartNumber" -o tsv
```

### 3. Device eligibility

Microsoft Entra joined or hybrid joined, MDM-enrolled, running Windows Enterprise,
Professional or Education edition (or co-managed).

### 4. RBAC

The operator needs permissions under the **Device configurations** category of their
Intune role. Creating a script package and assigning one can be separate rights in a
custom role, which produces the confusing case where creation succeeds and assignment
fails.

## Installation

Two supported paths. They produce **identical** results — the portal uploads the same two
generated files the CLI does. Pick whichever suits your change process.

Either way, **build first**. The remediation script you deploy does not exist in `src/`:
it is generated, with the watchdog payload compressed and SHA-256-stamped into it.

```zsh
zsh scripts/build.sh
```

| Output | Purpose |
|---|---|
| `build/Detect-DropboxWatchdog.ps1` | Detection — is the watchdog installed and healthy? |
| `build/Remediate-DropboxWatchdog.ps1` | Remediation — install/repair it |
| `build/DetectRemoval-DropboxWatchdog.ps1` | Detection for the *removal* package |
| `build/Uninstall-DropboxWatchdog.ps1` | Removal |
| `build/manifest.json` | Payload version + hash, for your change record |

---

### Path A — Intune admin center (portal)

```zsh
zsh scripts/build.sh && open build/
```

1. <https://intune.microsoft.com> → **Devices** → **Scripts and remediations** →
   **Remediations** → **+ Create script package**.
   (Older tenants: **Reports** → **Endpoint analytics** → **Proactive remediations**.)
2. **Basics** — name it `Dropbox client watchdog`. Put the `payloadVersion` from
   `build/manifest.json` in the description; that is how you will later tell which build
   a device is running.
3. **Settings**:

   | Field | Value |
   |---|---|
   | Detection script file | `build/Detect-DropboxWatchdog.ps1` |
   | Remediation script file | `build/Remediate-DropboxWatchdog.ps1` |
   | Run this script using the logged-on credentials | **No** |
   | Enforce script signature check | **No** |
   | Run script in 64-bit PowerShell | **Yes** |

   Two of those look wrong and are not. **Logged-on credentials = No** is the design:
   the script must be SYSTEM to write `%ProgramData%`, set ACLs, create the event source
   and register a task for *all* users — the watchdog it installs is what runs as the
   user.

   **64-bit = Yes** *diverges from Microsoft's generic recommendation of No*, and
   deliberately. Under the 32-bit host, WOW64 registry redirection sends
   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` to `WOW6432Node`,
   where it does not exist. The detection script maps interactive session SIDs to profile
   paths through that key, so under 32-bit it would find no profiles and silently report
   every session as missing a heartbeat. Microsoft's "No" is a sound default for simple
   scripts; it is wrong for this one.

4. **Assignments** — select your device group, open the assignment's schedule, set
   **Hourly / every 1 hour**, leave remediation enabled.
5. **Review + create**.

### Path B — command line

Prerequisites: `jq`, `curl`, and either a signed-in Intune profile (see
[Signing in when Intune lives on a second account](#signing-in-when-intune-lives-on-a-second-account))
or an app registration.

```zsh
zsh scripts/deploy-intune.sh --group "Dropbox Watchdog Devices" --dry-run   # inspect
zsh scripts/deploy-intune.sh --group "Dropbox Watchdog Devices"
```

`--group` takes a group display name or object id. Other options:

| Flag | Default | Notes |
|---|---|---|
| `--display-name <n>` | `Dropbox client watchdog` | Also the key used to find an existing package |
| `--publisher <p>` | `$DBW_PUBLISHER` or `Endpoint Engineering` | |
| `--interval-hours <n>` | `1` | Intune's fastest |
| `--skip-build` | off | Reuse existing `build/` output |
| `--dry-run` | off | Print the Graph payload and stop |

The script is create-or-update: it matches on display name, so re-running is safe.

### What happens on the device

Two different clocks, and they are easy to conflate:

| | |
|---|---|
| **Policy delivery** | The Intune Management Extension fetches remediation script policy after a device restart, after the IME service restarts, after a user signs in, and otherwise **once every 8 hours**. A new or updated package can take that long to arrive. |
| **Run schedule** | Once delivered, the assignment's schedule (hourly here) governs how often detection runs. |

So expect up to ~8 hours for first contact, not one hour. A restart or user sign-in pulls
it sooner, as does **Sync** from the portal or Company Portal.

The first remediation run installs the watchdog; the watchdog then starts in every
signed-in session within 30 minutes, and at every logon after that.

### Verifying the rollout

**Devices** → **Remediations** → your package → **Device status**. Read the
*Pre-remediation detection output* and *Post-remediation detection output* columns — the
scripts emit single-line strings sized for exactly that view:

| Output | Meaning |
|---|---|
| `NOT_COMPLIANT: payload missing` | First contact. Expected. |
| `REMEDIATED: Dropbox watchdog 1.0.0 - … (headless launcher)` | Installed; names the launcher it chose. |
| `COMPLIANT: … heartbeats fresh.` | Steady state. |
| `NOT_COMPLIANT: heartbeat for SID … is 140 min old` | Installed but not running in a session. Investigate. |
| `… NOTE: 1 session(s) running under restricted PowerShell …` | AppLocker/WDAC active. Supported; informational. |
| `FAILED: … ConstrainedLanguage … in the SYSTEM context` | WDAC is constraining SYSTEM. Allow-listing required. |

The portal caches these; allow a couple of check-in cycles.

---

## Updating

Bump `$Script:PayloadVersion` in `src/payload/DropboxWatchdog.ps1`, then rebuild.

The version bump is what drives the rollout: detection compares the deployed version and
hash against the ones baked into it, reports non-compliant, and remediation writes the new
payload. Any watchdog loop already running in a session notices the version change and
exits, so the scheduled task starts the new one. **No reboot, no logoff.**

### Portal

Edit the package → **Settings** → **re-upload both files**.

> ### Upload both files, every time
>
> The detection and remediation are a matched pair: detection enforces the exact SHA-256
> and version that remediation embeds. Upload a new remediation but keep the old
> detection and every device reports non-compliant *forever* while remediation reinstalls
> the same payload hourly. The reverse produces the same loop. `scripts/build.sh`
> regenerates both together for this reason — never hand-edit either file in the portal
> text box.

### CLI

```zsh
zsh scripts/update-intune.sh
zsh scripts/update-intune.sh --group "Dropbox Watchdog Devices"   # also refresh assignment
```

Updates content in place on the existing package; assignments are left alone unless you
pass `--group`.

---

## Teardown

> **Deleting the Intune package does not uninstall anything.** It stops the package
> running; every device keeps the scheduled task and the `%ProgramData%` install
> indefinitely. Removal is a two-phase process.

### Phase 1 — deploy the removal package

**Portal** — create a *second* script package assigned to the same group:

| Field | Value |
|---|---|
| Detection script file | `build/DetectRemoval-DropboxWatchdog.ps1` |
| Remediation script file | `build/Uninstall-DropboxWatchdog.ps1` |
| Run using logged-on credentials | **No** |
| Run script in 64-bit PowerShell | **Yes** |

Then delete the original `Dropbox client watchdog` package.

**CLI** — both steps in one command:

```zsh
zsh scripts/teardown-intune.sh --group "Dropbox Watchdog Devices" --deploy-cleanup
```

The uninstall neutralises the config first, so any watchdog loop running in a user session
stands down on its own at the next poll rather than being orphaned with its script deleted
underneath it. Then it removes the scheduled task, the install directory, the event source
and per-user state.

### Phase 2 — purge, once the fleet is clean

Wait until the removal package reports compliant across the group — long enough for every
device to check in, typically a few days including anything powered off.

```zsh
zsh scripts/teardown-intune.sh --purge     # or delete the package in the portal
```

Deleting the removal package early leaves the watchdog installed on any device that has
not yet checked in.

### Removing a single device by hand

From an elevated prompt, run the generated uninstall script:

```powershell
.\Uninstall-DropboxWatchdog.ps1            # from build/
.\Uninstall-DropboxWatchdog.ps1 -KeepLogs  # leave per-user logs for diagnosis
```

It is idempotent and safe on a device that never had the watchdog.

Other teardown flags: `--delete-only` (delete the main package without deploying cleanup —
devices keep the watchdog), `--cleanup-name`, `-y/--yes` to skip confirmation prompts.

## Operating it

**Is it working on this device?** (elevated prompt)

```powershell
Get-ScheduledTask -TaskPath '\DropboxWatchdog\' | Format-List TaskName, State
Get-Content "$env:LOCALAPPDATA\DropboxWatchdog\watchdog.log" -Tail 40
Get-Content "$env:LOCALAPPDATA\DropboxWatchdog\state.json" | ConvertFrom-Json
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='DropboxWatchdog'} -MaxEvents 50
```

**Run one check by hand, in the current user's session:**

```powershell
& "$env:ProgramData\DropboxWatchdog\bin\DropboxWatchdog.ps1" -Mode Once -Verbose
```

**Pause it** (e.g. while troubleshooting, or during a Dropbox migration):

```powershell
New-Item "$env:ProgramData\DropboxWatchdog\pause.marker" -ItemType File   # whole device
New-Item "$env:LOCALAPPDATA\DropboxWatchdog\pause.marker" -ItemType File  # one user
```

Delete the marker to resume. Nothing else needs restarting.

**Tune it** without re-deploying by editing
`C:\ProgramData\DropboxWatchdog\bin\version.json` — but note the next Intune remediation
run rewrites that file. For a fleet-wide change, edit `RuntimeConfig` in
`src/common/SharedContract.ps1`, bump the payload version, and run `update-intune.sh`.

### How the watchdog is launched windowlessly

The scheduled task runs `conhost.exe --headless powershell.exe … -Mode Service`, so users
never see a console flash — neither at logon nor when the 30-minute supervisor trigger
fires. Before registering the task, the remediation actually *runs*
`conhost.exe --headless cmd.exe /c exit 0` and falls back to launching `powershell.exe`
directly if that fails, rather than registering a task that would never start. Detection
accepts either launcher, so a device that fell back is not flagged non-compliant forever.
The remediation's output says which one it chose.

### Security notes

* `C:\ProgramData\DropboxWatchdog` has inheritance removed and is granted SYSTEM and
  Administrators full control, **`BUILTIN\Users` read + execute only**. The payload runs in
  every user's session, so a standard user must not be able to modify it.
* The remediation verifies the payload's SHA-256 after writing it and **throws** if it does
  not match; detection re-verifies the hash on every run, so tampering shows up as
  non-compliant and is repaired automatically.
* Nothing is ever sent off the device. All state is local plus the Application event log.

### Known limits

* Dropbox's health signal is "the process exists in this session". The watchdog cannot tell
  a running-but-not-syncing client from a healthy one — Dropbox exposes no supported
  interface for that. It fixes the reported symptom (process exits, sync stops), not a
  hypothetical silent-stall.
* Crash-loop protection means a device whose Dropbox dies immediately every time will be
  left down for the remainder of the hour, by design. **Event ID 3001 is the signal to
  investigate** rather than to keep restarting.
* The watchdog treats "no Dropbox installed for this user" as normal and does nothing —
  it never installs Dropbox.

---

## License

MIT — see [LICENSE](LICENSE).

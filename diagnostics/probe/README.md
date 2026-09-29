# Probe: why won't the remediation package save?

Three tiny scripts that need no privileges and change nothing except one file in
their own temp folder. Deploy them to **the same group that is failing** and compare
what saves, assigns and runs.

| File | Where it goes |
|---|---|
| `Probe-Detect.ps1` + `Probe-Remediate.ps1` | **Remediations** — a script package |
| `Probe-PlatformScript.ps1` | **Platform scripts** — a different Intune feature |

The files are pure ASCII with no BOM, so they upload cleanly.

## The tests

Create each of these and assign it to the failing group. Stop at the first one that
fails; that row tells you where the problem is.

| # | What to create | Settings |
|---|---|---|
| **P1** | Platform script `Probe-PlatformScript.ps1` | logged-on credentials **No**, 64-bit **Yes** |
| **R1** | Remediation package, Probe pair | logged-on credentials **Yes** (runs as the user) |
| **R2** | Remediation package, Probe pair | logged-on credentials **No** (SYSTEM), 64-bit **Yes** |
| **R3** | *Optional.* Same as R2, assigned to **All devices** instead of the group | |

Location in the Intune admin center: **Devices** → **Scripts and remediations** →
the **Remediations** or **Platform scripts** tab.

## Reading the results

| Result | What it means | Next step |
|---|---|---|
| **P1 fails** | Not Remediations-specific. Your role can't assign scripts to this group at all: RBAC, scope tags, or the group itself | Check the role's **Device configurations** rights and scope tags |
| **P1 saves, R1 and R2 fail** | The gate is specific to Remediations. The run context is **not** the cause | Turn on **Tenant administration → Connectors and tokens → Windows data → *I confirm that my tenant owns one of these licenses***. Also check the role has the Remediations rights |
| **R1 saves, R2 fails** | The SYSTEM context really is what's being refused (unusual) | Look for a policy that restricts SYSTEM-context scripts |
| **R2 fails, R3 saves** | The problem is the group, not the feature or context | Check scope tags on the group, or whether your role's scope includes it |
| **R1 and R2 both save** | The feature, context and group are all fine. Something about the real package's files is being rejected | Upload the real `Detect-DropboxWatchdog.ps1` with `Probe-Remediate.ps1`, then the reverse, to find which file |

## Getting the real error message

When the portal's message is useless, the real one is almost always in the Graph
response the portal gets back:

1. Open the browser's developer tools (**F12**), go to the **Network** tab, and tick
   *Preserve log*.
2. Try to save or assign again.
3. Find the failing request to `graph.microsoft.com`. It will be a `POST` to
   `…/deviceHealthScripts` (create) or `…/deviceHealthScripts/{id}/assign` (assign),
   usually red with a 4xx status.
4. Open its **Response** tab. The `error.code` and `error.message` there are the
   diagnosis. Keep the `request-id` and `client-request-id` headers in case you need
   Microsoft support.

## What you see on a device once it works

These are policy delivery times, not run times: the Intune Management Extension checks
for new script policy every 8 hours, or when the device restarts or a user signs in.
**Sync** from the portal makes it check sooner.

**Remediations → your probe package → Device status**:

```
Pre-remediation:  PROBE NOT_COMPLIANT: no marker yet, remediation should run | user=nt authority\system | 64-bit host | ps=5.1.26100.1 | lang=FullLanguage | session=0
Remediation:      PROBE REMEDIATED: wrote C:\Windows\SystemTemp\IntuneRemediationProbe.marker | user=nt authority\system | ...
Post-remediation: PROBE COMPLIANT: remediation ran at 2026-09-29T14:02:11Z | user=nt authority\system | ...
```

R1 should show your own account and a non-zero `session`. If you see `lang=ConstrainedLanguage`
there, AppLocker or WDAC is active for that user.

The platform script's only portal signal is success or failure. Its log is at
`%TEMP%\IntunePlatformScriptProbe.log` for whichever account it ran as. For SYSTEM that's
`C:\Windows\SystemTemp` on current Windows 11 builds, or `C:\Windows\Temp` on older ones.

## Cleanup

Delete the probe packages when you're done. On the device they leave only a marker file
and a log line in a temp folder, both harmless.

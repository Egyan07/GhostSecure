<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white" alt="Windows">
  <a href="https://github.com/Egyan07/GhostSecure/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Egyan07/GhostSecure/ci.yml?label=CI&logo=githubactions&logoColor=white" alt="CI"></a>
</p>

# GhostSecure

A Windows service that reads the Security event log and raises an alert the moment an Active Directory attack technique runs on the domain.

## Why this exists

A domain controller records almost everything an attacker needs to do. Kerberoasting shows up as a burst of RC4 service tickets. DCSync shows up as replication rights used by an account that is not a DC. Pass-the-Hash shows up as a network logon with no interactive logon before it. All of that is already in the event log, and none of it is read unless someone has built detection on top of it.

GhostSecure is that detection layer. It runs as a service, starts at boot, needs nobody logged in, and turns the events worth caring about into an alert that names the account, the source machine and the event ID.

It is an early warning system, not an EDR. It detects, it does not block, and it does not replace a SIEM.

## What it detects

| Technique | Event ID | What has to be true before it fires |
|---|---|---|
| Kerberoasting | 4769 | RC4 service ticket request for an account that has no business requesting one |
| Pass-the-Hash | 4624 | NTLM network logon with no prior interactive logon for that user in the window |
| DCSync | 4662 | Replication rights invoked by an account that is not a known domain controller |
| Golden Ticket | 4768, 4769 | TGT with a lifetime or encryption type a real KDC does not produce |
| AS-REP Roasting | 4768 | Ticket request for an account with pre-authentication disabled |
| LDAP recon / BloodHound | 1644 | LDAP query burst above the threshold inside the window, one host at a time |
| Skeleton Key | 4673 | Sensitive privilege use, or a service name matching known Mimikatz drivers |
| Log cleared or service dropped | 1102, 7045 | Security log wiped, or a new service installed from an unusual binary |

Eight techniques across seven detector modules. Skeleton Key, log clearing and service installation share one module because they are the same stage of an intrusion.

## How an alert reaches you

- **Log file.** Every alert is appended to `C:\SecurityLogs\ad_attack_log.txt` with timestamp, attack type, attacker account, source machine and event ID.
- **Desktop popup.** A window on the machine running the service.
- **`msg.exe`.** Message box on `ADMIN_HOSTNAME` and anything in `ADDITIONAL_ALERT_HOSTS`, so the alert lands on your workstation rather than the DC console.
- **Email (optional).** SMTP over TLS with certificate verification. The password comes from `GHOSTSECURE_SMTP_PASSWORD` and is never stored in config.

A repeat of the same technique from the same attacker is suppressed for a cooldown window, so one noisy event does not fill the log with a thousand copies of itself.

## Requirements

- Windows Server 2016 or later, or Windows 10/11 joined to the domain
- Python 3.10+
- Domain Administrator rights for installation
- Windows Advanced Audit Policy logging enabled (below)

## Install

```bash
pip install pywin32 ldap3
```

1. Copy the folder to the domain controller or a domain-joined machine.
2. Edit `config.py`:
   - `ADMIN_HOSTNAME` is the workstation where popups should appear
   - `KNOWN_DOMAIN_CONTROLLERS` is the list of your DCs, for example `["DC01", "DC02"]`
   - `DOMAIN_NAME` and `LDAP_SERVER` point at your domain
3. Right-click `Install.bat` and run as administrator.
4. Confirm it is alive:

```cmd
sc query GhostSecure2ADDetector
```

`STATE: RUNNING` means the service is up. `python main.py --test` runs a self-check.

## Audit policy

GhostSecure can only detect what Windows records. On the Default Domain Controllers Policy, enable Success and Failure for:

| Category | Policy |
|---|---|
| Account Logon | Audit Kerberos Authentication Service |
| Account Logon | Audit Kerberos Service Ticket Operations |
| DS Access | Audit Directory Service Access |
| Logon/Logoff | Audit Logon |
| Privilege Use | Audit Sensitive Privilege Use |
| System | Audit Security State Change |

Then run `gpupdate /force` on the DC. Without these, the service runs and detects nothing.

## Configuration

Everything lives in `config.py`. The thresholds are the part worth tuning:

| Setting | Default | Meaning |
|---|---|---|
| `ADMIN_HOSTNAME` | `ADMINPC` | Workstation that receives popups |
| `ADDITIONAL_ALERT_HOSTS` | `[]` | Extra recipients for `msg.exe` |
| `ENABLE_EMAIL_ALERTS` | `False` | Turns SMTP on |
| `LDAP_RECON_THRESHOLD` | `500` | LDAP queries inside the window before recon fires |
| `LDAP_RECON_WINDOW_SECONDS` | `60` | Window for the count above |
| `GOLDEN_TICKET_MAX_LIFETIME_SECONDS` | `10` hours | TGT lifetime above this is treated as forged |
| `KERB_WEAK_ENCRYPTION_TYPE` | `0x17` | RC4, the encryption type Kerberoasting depends on |
| `PTH_INTERACTIVE_WINDOW_SECONDS` | `28800` | How far back to look for an interactive logon |
| `SKELETON_KEY_SERVICE_NAMES` | `mimidrv`, `mimikatz` | Service names that trigger on install |

## Command line

```cmd
GhostSecure2.exe --console     run the detection loop in the foreground
GhostSecure2.exe --gui         status dashboard, live counts and alert history
GhostSecure2.exe --test        self-test
GhostSecure2.exe --version     version information
```

The same modes work through `python main.py --console`, `--gui`, `--test` and `--version`.

## Tests

53 unit tests across all seven detectors, the alert manager, the AD helpers and the time helpers.

```bash
pip install pytest pytest-cov
pytest tests/ -v
```

CI runs the suite on Python 3.10, 3.11 and 3.12, with flake8 and a coverage report.

## Structure

```
GhostSecure/
├── main.py                    service entry point and CLI
├── config.py                  everything you tune
├── core/
│   ├── event_reader.py        Security log reader (pywin32)
│   ├── detector_engine.py     routes each event through every detector
│   └── alert_manager.py       log, popup, msg.exe, email, deduplication
├── detectors/                 one module per technique
├── utils/
│   ├── ad_helpers.py          LDAP and GSSAPI queries against the DC
│   └── time_helpers.py        Windows timestamp parsing
├── gui/status_dashboard.py    Tkinter dashboard
└── tests/
```

## Limits

| Limit | Detail |
|---|---|
| Audit policy is the floor | No policy, no detections. This is the first thing to check when nothing fires |
| One host at a time | Install per DC, or point it at a collector that forwards the Security channel |
| No correlation across hosts | Each install decides alone. A low and slow attack split across two DCs can stay under the thresholds |
| No blocking | It alerts, it does not disable accounts or drop connections |
| `msg.exe` | Missing on Windows Home, and blocked by some endpoint agents. The log and email paths still work |
| Windows only | No Linux or macOS support |

## Changelog

**2.1.x**

- Race condition fixed in `detectors/golden_ticket.py`, writes to the TGT map now happen inside the lock
- SMTP connection closed through a context manager so a failed send cannot leak the socket
- Alert email moved to a daemon thread, the detection loop no longer waits on the mail server
- SMTP password read from the environment, never from config
- LDAP authentication moved to SASL/GSSAPI after the NTLM empty-password bind was found broken
- Event reader tracks `EventRecordID` so a restart does not replay the same events
- GUI stats moved to a background thread, the dashboard no longer freezes during a burst

**2.0**

- First release, seven detectors and the service architecture

## Author

Egyan07, [github.com/Egyan07](https://github.com/Egyan07)

Built as an independent project and released for anyone running a small domain without a SOC behind it.

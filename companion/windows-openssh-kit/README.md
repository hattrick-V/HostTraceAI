# Windows SSH Enable Kit

**English** | [简体中文](README_CN.md)

A companion kit for [HostTraceAI](../../README.md). It temporarily enables an
SSH server on a Windows host so the platform can connect to it over SSH/MCP for
investigation — and cleanly removes everything afterwards.

The kit bundles three official
[PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH)
releases and picks one that actually works on the target machine, instead of
installing the newest build and hoping for the best.

## The problem it solves

Dropping a recent Win32-OpenSSH onto an older Windows server often fails in a
confusing way: installation succeeds, the service reports `RUNNING`, the port is
open, and the SSH banner is served — but every client connection dies with:

```
Connection reset by <IP> port 22
```

`ssh -vvv` shows the banner arriving, then the reset lands right after the
client sends `KEXINIT`.

The cause is that OpenSSH 9.8 split `sshd` into two processes:
`sshd.exe` (listener) and `sshd-session.exe` (per-connection session). On an
older Windows build, `sshd.exe` starts fine, so the service looks healthy and
the banner is served — but the session child process is killed when it touches
system APIs that do not exist there. Port open, protocol dead after two steps.
Upstream documents 9.8/10.x as requiring Windows 10 1809+ / Server 2019+.

A second, less obvious cause of the same symptom: the program directory must be
writable **only** by SYSTEM and Administrators. Running OpenSSH from the
Desktop, the Downloads folder, or a USB stick triggers the same reset.

## How it works

`bin/` holds three **unmodified** upstream builds:

| Version | Upstream release | Architecture | Targets |
|---|---|---|---|
| `7.7.2.0` | v7.7.2.0p1-Beta | single-process `sshd` | Windows 7 / 2008 R2 / 2012 / 2012 R2 / 2016 |
| `8.9.1.0` | v8.9.1.0p1-Beta | intermediate | fallback |
| `10.0.0.0` | 10.0.0.0p2-Preview | split `sshd` + `sshd-session` | Windows 10 1809+ / Server 2019+ |

`1-启用SSH.bat` then:

1. Reads the OS build number and builds a version ladder — newest first on
   modern systems, oldest first on legacy ones.
2. Copies that version to `C:\Program Files\OpenSSH-Win64` and tightens the
   directory ACL (SYSTEM and Administrators writable, Authenticated Users
   read+execute). Permissions are applied by **SID**, so the result is identical
   on English and Chinese systems.
3. Generates host keys, writes `sshd_config`, and installs the `sshd` service.
4. **Self-tests with a real key exchange** over the loopback interface via
   `ssh-keyscan`. Getting the host public key back means the version genuinely
   works; getting only the `SSH-2.0` banner means the session process is dead —
   exactly the reset failure. On failure it automatically falls back to the next
   version and retries.
5. If all three versions fail, it runs `sshd -ddd` and prints the debug output
   so the real error is visible instead of a generic failure.
6. Opens the firewall port (default 22).

`2-停止卸载.bat` reverses it: stops the service, removes the firewall rule, and
either uninstalls the service and deletes the program directory (if this kit
installed it) or restores the original `sshd_config` from backup (if the machine
already had its own `sshd`, in which case the existing service is left alone).

## Usage

```text
1. Copy the whole kit folder to the target machine (any location works —
   the script installs to Program Files itself).
2. Run 1-启用SSH.bat as Administrator.
3. After the investigation, run 2-停止卸载.bat.
```

The script self-elevates via UAC if launched without administrator rights.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SSH_TRACE_PW` | — | Set the `administrator` password non-interactively |
| `SSH_TRACE_PORT` | `22` | Use a different port |
| `SSH_TRACE_INSTDIR` | `%ProgramFiles%\OpenSSH-Win64` | Install to a different directory |
| `SSH_TRACE_FORCE_INSTALL` | — | Take over even if another `sshd` is already installed |
| `SSH_TRACE_FAKEBUILD` | — | Force a version ladder (debugging) |
| `SSH_TRACE_TEST=1` | — | **Dry run**: exercise the real subroutines without installing a service or modifying the system |

`SSH_TRACE_TEST=1` is the safe way to validate the script on a new machine
before letting it touch anything.

## Compatibility

| System | Build | Default version tried |
|---|---|---|
| Windows Server 2012 / 2012 R2 | 9200 / 9600 | `7.7.2.0` |
| Windows Server 2016 | 14393 | `7.7.2.0` |
| Windows Server 2019 | 17763 | `10.0.0.0` |
| Windows 10 / 11 | 19041+ / 22000+ | `10.0.0.0` |
| Windows 7 / Server 2008 R2 | 7601 | `7.7.2.0` (requires KB2999226, the Universal C Runtime) |

The table is only the starting order — the self-test result decides. A version
that fails is skipped automatically.

## Troubleshooting

```text
Log:            ssh-trace.log in the kit directory
Service status: sc query sshd
```

**Is the service actually alive?** An open port does not mean a working
service:

```cmd
bin\7.7.2.0\ssh-keyscan.exe -T 8 -t rsa,ed25519 127.0.0.1
```

- Prints `127.0.0.1 ssh-ed25519 AAAA...` — healthy.
- Prints only `# 127.0.0.1:22 SSH-2.0-...` — the service is up but the session
  process cannot start. This is the reset failure.

**Foreground debugging** (shows the raw error):

```cmd
cd /d "C:\Program Files\OpenSSH-Win64"
sshd.exe -ddd -f "%ProgramData%\ssh\sshd_config"
```

Then connect from another machine and watch the output.

**Port already in use:** `netstat -ano | findstr :22`

**All three versions failed:** the script prints the common causes — directory
permissions, a missing runtime on very old systems, endpoint protection killing
the `sshd` child process, or a port conflict.

## Getting the kit

This repository carries the scripts and documentation. The 28 MB of upstream
OpenSSH binaries are **not** committed — they are third-party redistributables
and belong in a versioned artifact, not in git history.

Download the assembled kit from the
[releases page](https://github.com/hattrick-V/HostTraceAI/releases), or build it
yourself from the upstream releases:

```powershell
powershell -ExecutionPolicy Bypass -File build-kit.ps1
```

The script downloads the three pinned upstream releases, verifies each one
against a hard-coded SHA-256 digest, lays out `bin\<version>\`, and produces
`HostTraceAI-WindowsSSHKit-<version>.zip`. It only downloads, verifies and
packages — it installs nothing, registers no service, and modifies no system
state. Running it also leaves `bin\` populated next to the script, so a plain
checkout becomes directly usable.

The pinned inputs are:

| `bin\` | Upstream tag | Archive SHA-256 |
|---|---|---|
| `7.7.2.0` | `v7.7.2.0p1-Beta` | `8631f000…34fa5bce` |
| `8.9.1.0` | `v8.9.1.0p1-Beta` | `b3d31939…0befb9fc` |
| `10.0.0.0` | `10.0.0.0p2-Preview` | `23f50f34…7b43aba5` |

Every `bin\` tree was compared byte-for-byte against the corresponding upstream
archive, so the kit ships exactly what upstream published — no patches and no
local rebuilds. If upstream ever replaces an asset, the build fails loudly
rather than quietly shipping different binaries.

### What's in the archive

```text
HostTraceAI-WindowsSSHKit-<version>\
    1-启用SSH.bat                  enable SSH (self-elevating)
    2-停止卸载.bat                 stop, uninstall and restore
    OpenSSH-Win64-兼容性说明.txt   original Chinese field notes (GBK)
    README.md / README_CN.md       this documentation
    THIRD-PARTY-NOTICES.md         bundled third-party license texts
    LICENSE                        Apache-2.0
    build-kit.ps1                  rebuilds the archive from upstream
    bin\7.7.2.0\                   19 files
    bin\8.9.1.0\                   26 files
    bin\10.0.0.0\                  33 files
```

## Notes on encoding

`1-启用SSH.bat`, `2-停止卸载.bat`, and `OpenSSH-Win64-兼容性说明.txt` are
**GBK-encoded with CRLF line endings**, because the scripts run `chcp 936` and
print Chinese text. `.gitattributes` marks them `-text` so git never rewrites
them. **Do not convert them to UTF-8** — the console output would garble.

The readable Chinese documentation is available as UTF-8 in
[`README_CN.md`](README_CN.md).

The kit archive stores file names as UTF-8 with the ZIP language-encoding flag
set, which 7-Zip, WinRAR, and Windows 10 or later Explorer all honour. Should
you extract with an older tool and see the Chinese names garbled, the kit still
works: neither script invokes the other or reads a sibling file by name, so the
batch files run correctly whatever they end up being called.

`build-kit.ps1` itself is deliberately **ASCII-only**. Windows PowerShell 5.1
decodes `.ps1` files that carry no BOM using the system ANSI code page, so
non-ASCII source would corrupt on some hosts.

## Scope and authorization

This kit **enables the built-in `administrator` account, sets its password, and
opens a firewall port**. It is intended solely for authorized host
investigation and incident response, on hosts you are explicitly permitted to
access. `2-停止卸载.bat` exists so the change is fully reversible — run it when
the investigation ends.

Do not use it on systems you do not own or have written authorization to
investigate.

## Licensing

The scripts and documentation in this directory are licensed under the Apache
License 2.0 — see [`LICENSE`](LICENSE) for the full text, or the repository
[`LICENSE`](../../LICENSE) for the project as a whole.

The bundled OpenSSH binaries are **not** covered by that license. They are
redistributed under their own upstream terms — OpenSSH (BSD/ISC/MIT), OpenSSL,
LibreSSL, zlib, libfido2, and libcbor. See
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for the full texts and
required acknowledgements. Upstream project:
[PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH).

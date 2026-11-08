# rslocalehook

A Rust rewrite of the [Locale Remulator](https://github.com/InWILL/Locale_Remulator)
`LRProc` + `LRHook` components: run a Windows program as if the system were
configured for a different locale, ANSI code page and time zone, without
changing any system settings.

It works by launching the target process suspended, injecting a hook DLL, and
detouring the ANSI/Unicode Win32 APIs the program uses to detect the system
locale (`GetACP`, `GetUserDefaultLCID`, `GetTimeZoneInformation`, the
`...A` text/font/clipboard APIs, and so on).

This is a from-scratch reimplementation; only the launcher and hook pieces are
kept. The original project is licensed under LGPL-3.0, and so is this one.

## Layout

| Crate | Output | Role |
|-------|--------|------|
| `crates/common` | lib | Shared `Config` and the suspended-launch / DLL-injection code |
| `crates/cli` | `rslocalehook.exe` | Command line launcher (the `LRProc` equivalent) |
| `crates/hook` | `rslocalehook_hook.dll` | Injected detour DLL (the `LRHook` equivalent) |

`rslocalehook.exe` expects `rslocalehook_hook.dll` to sit next to it.

## Build

```powershell
cargo build --release
```

Both artifacts land in `target\release\`. Build for the architecture that
matches your targets (a 64-bit build injects into 64-bit processes).

## Usage

```
rslocalehook run <PROGRAM> --nls <LCID> [--timezone <IANA>] [--codepage <CP>] [--hookime] [--hooklcid] [--args "<ARGS>"]
```

Example (run a program as Japanese, Tokyo time):

```
rslocalehook run D:\path\to\program.exe --nls 0411 --timezone Asia/Tokyo --hookime --args "--Argument 1"
```

### Options

| Option | Meaning |
|--------|---------|
| `<PROGRAM>` | Path to the executable to launch. |
| `--nls <LCID>` | Locale id in hexadecimal (e.g. `0411` = Japanese; `0x` prefix allowed). |
| `--timezone <IANA>` | IANA time-zone name (e.g. `Asia/Tokyo`); sets the spoofed UTC bias. |
| `--codepage <CP>` | Override the ANSI code page. Defaults to the one derived from `--nls`. |
| `--hookime` | Also hook IME composition APIs. |
| `--hooklcid` | Enable LCID-related window-class hooking (reserved). |
| `--elevate` | Run the target elevated. If not already admin, prompts for UAC. |
| `--no-hook <PATTERN>` | Exclude a module/process from hooking. Repeatable. Added on top of the built-in list. |
| `--hook-anticheat` | Hook anti-cheat/DRM modules too (disables the built-in exclusion list). |
| `--args "<ARGS>"` | Extra arguments passed verbatim to the target. |

### Excluding modules and subprocesses (`--no-hook`)

`--no-hook <PATTERN>` takes a case-insensitive substring and can be repeated.
It does two things:

- **Child processes**: a child whose application name or command line contains a
  pattern is launched *without* injecting the hook DLL (so it — and anything it
  loads — runs un-hooked). This generalises the original project's hardcoded
  `BlackXchg.aes` exclusion.
- **In-process modules**: the launcher cannot literally remove a global inline
  hook for a single DLL, but the hook DLL records the address range of any
  loaded module whose name matches a pattern and, on every hooked call, checks
  the caller's return address. Calls originating from an excluded module are
  passed straight through to the original API with no locale/code-page/path
  rewriting. The address table is seeded at startup and updated via a
  `LoadLibraryEx` hook, so modules loaded later are covered too.

Example — leave a packer/anti-cheat such as GPK untouched:

```
rslocalehook run game.exe --nls 0411 --no-hook GT.dll --no-hook Sddyn --no-hook GPK
```

Caveats: this changes *behaviour* only — it does not hide the patched API bytes,
so a module that scans its own process for inline hooks will still see them.
There is no runtime cost until a matching module is actually present.

### Built-in anti-cheat exclusions

By default the patterns above are combined with a built-in list of well-known
anti-cheat / DRM / packer modules, so they are left un-hooked without any extra
flags. The list currently covers (by distinctive substrings):

- nProtect GameGuard, Wellbia XIGNCODE3, AhnLab HackShield
- Tencent TenProtect / Anti-Cheat Expert (ACE), EasyAntiCheat, BattlEye
- Riot Vanguard, PunkBuster, miHoYo mhyprot, Denuvo Anti-Cheat
- GPK protection components (`sddyn`, `sdictn`, `sdgame`, `gpk.`, `gpe.`)

Pass `--hook-anticheat` to disable this default list (for example to debug, or
if a default substring collides with something in your target). `--no-hook`
patterns you supply are always applied regardless.

### No console window

The launcher is built as a *windows* subsystem binary, so starting it (from a
shortcut, `.lnk`, or Explorer) never opens a console window. When you run it
from an existing terminal it attaches to that console, so `--help` and error
messages still appear there. When there is no console (e.g. a shortcut) a fatal
error is shown in a message box instead.

Trade-off: because it is a GUI-subsystem program, `cmd`/PowerShell do not block
on it, so an interactive shell returns to the prompt immediately and the child
process's exit code is not propagated back to the shell.

### Elevation

With `--elevate`, if the launcher is not already running as administrator it
re-launches itself through a UAC prompt (the `runas` shell verb) and waits for
that elevated instance to finish. The elevated instance performs the normal
suspended-create + inject, so the launcher and the target share the same
(elevated) integrity level and injection still works. Declining the UAC prompt
makes the command fail with an "elevation was declined" error.

The launcher derives the ANSI code page from the LCID via `GetLocaleInfoW`
(`LOCALE_IDEFAULTANSICODEPAGE`) and the time-zone bias from the IANA name, then
passes the settings to the DLL through environment variables that the child
process inherits.

## What gets hooked

- Code pages: `GetACP`, `GetOEMCP`, `GetConsoleCP`, `GetConsoleOutputCP`, `GetCPInfo`
- Conversions: `MultiByteToWideChar`, `WideCharToMultiByte`
- Locale ids: `GetThreadLocale`, `Get{System,User}Default{LCID,UILanguage,LangID}`, `GetLocaleInfoA/W`
- DBCS/traversal: `IsDBCSLeadByteEx`, `CharNextExA`, `CharPrevExA`
- Time zone: `GetTimeZoneInformation`
- Text/UI: `CreateWindowExA`, `MessageBoxA`, `SendMessageA` (text messages), `DrawTextExA`
- Fonts: `CreateFontA`, `CreateFontIndirectA`
- Clipboard: `GetClipboardData`, `SetClipboardData` (CF_TEXT)
- File system: `CreateFileA`, `CreateDirectoryA`
- Child processes: `CreateProcessA`, `CreateProcessW` (re-injects the DLL so children inherit the locale)
- IME (with `--hookime`): `ImmGetCompositionStringA`

## Limitations

- Injection is same-architecture only (build an x64 launcher/DLL for x64 targets).
- The `SendMessageA` text handling covers the common window-text and
  list/combo-box string messages; some rarer messages fall through unchanged.
- `CreateFontIndirectExA` and `ImmGetCandidateListA` from the original are not
  yet reimplemented.

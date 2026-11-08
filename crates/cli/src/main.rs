//! `rslocalehook` command line launcher.
//!
//! Example:
//! ```text
//! rslocalehook run D:\path\to\program.exe --nls 0411 --timezone Asia/Tokyo --hookime --args "--Argument 1"
//! ```
//!
//! Built as a *windows* subsystem binary so launching it (e.g. from a shortcut)
//! never pops up a console window. When started from an existing terminal it
//! attaches to that console so `--help` and error messages are still visible;
//! otherwise fatal errors are shown in a message box.
#![windows_subsystem = "windows"]

use anyhow::{bail, Context, Result};
use chrono::{TimeZone, Utc};
use chrono_tz::{OffsetComponents, Tz};
use clap::{Args, Parser, Subcommand};
use rslocalehook_common::{to_wide, Config};
use windows_sys::Win32::Globalization::{
    GetLocaleInfoW, LOCALE_IDEFAULTANSICODEPAGE, LOCALE_RETURN_NUMBER,
};
use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

#[derive(Parser)]
#[command(name = "rslocalehook", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Launch a program under an emulated locale.
    Run(RunArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Path to the target program to run.
    program: String,

    /// Locale id (LCID) in hexadecimal, e.g. 0411 for Japanese. A `0x` prefix
    /// is accepted.
    #[arg(long)]
    nls: String,

    /// IANA time zone name used to spoof the time zone bias, e.g. Asia/Tokyo.
    #[arg(long)]
    timezone: Option<String>,

    /// Override the ANSI code page. By default it is derived from `--nls`.
    #[arg(long)]
    codepage: Option<u32>,

    /// Hook IME composition / candidate list APIs.
    #[arg(long)]
    hookime: bool,

    /// Hook window-class registration for LCID spoofing.
    #[arg(long)]
    hooklcid: bool,

    /// Run the target program elevated (prompts for UAC if not already admin).
    #[arg(long)]
    elevate: bool,

    /// Do not hook calls originating from, or inject into child processes
    /// matching, this case-insensitive substring (module/exe name or command
    /// line). Added on top of the built-in anti-cheat list. May be repeated.
    #[arg(long = "no-hook", value_name = "PATTERN")]
    no_hook: Vec<String>,

    /// Also hook known anti-cheat / DRM modules (disables the built-in
    /// `--no-hook` default list).
    #[arg(long)]
    hook_anticheat: bool,

    /// Additional arguments passed verbatim to the target program.
    #[arg(long, allow_hyphen_values = true)]
    args: Option<String>,
}

fn main() {
    // Best effort: attach to the parent console (if any) so CLI output stays
    // visible when invoked from a terminal, without ever creating a new window.
    let has_console = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 };

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // clap uses the "error" channel for --help/--version too.
            let text = error.render().to_string();
            if has_console {
                let _ = error.print();
            } else {
                show_message(&text, MB_OK);
            }
            std::process::exit(error.exit_code());
        }
    };

    let result = match cli.command {
        Command::Run(args) => run(args),
    };

    if let Err(error) = result {
        report_error(&error, has_console);
        std::process::exit(1);
    }
}

/// Presents a fatal error on the console if attached, otherwise in a dialog.
fn report_error(error: &anyhow::Error, has_console: bool) {
    let message = format!("{error:#}");
    if has_console {
        eprintln!("error: {message}");
    } else {
        show_message(&format!("Error: {message}"), MB_ICONERROR);
    }
}

/// Shows a modal message box owned by no window.
fn show_message(text: &str, style: u32) {
    let text_w = to_wide(text);
    let caption_w = to_wide("rslocalehook");
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text_w.as_ptr(),
            caption_w.as_ptr(),
            style,
        );
    }
}

fn run(args: RunArgs) -> Result<()> {
    let lcid = parse_lcid(&args.nls)
        .with_context(|| format!("invalid --nls value: {}", args.nls))?;

    let codepage = match args.codepage {
        Some(cp) => cp,
        None => ansi_codepage_for(lcid).unwrap_or_else(|| {
            eprintln!(
                "warning: could not resolve an ANSI code page for LCID {lcid:#06x}; using CP_ACP"
            );
            0
        }),
    };

    let bias = match &args.timezone {
        Some(name) => bias_minutes(name)
            .with_context(|| format!("invalid --timezone value: {name}"))?,
        None => 0,
    };

    let config = Config {
        codepage,
        lcid,
        bias,
        hook_ime: args.hookime,
        hook_lcid: args.hooklcid,
        no_hook: effective_no_hook(&args),
    };

    let program = std::path::absolute(&args.program)
        .with_context(|| format!("resolving program path: {}", args.program))?;
    if !program.exists() {
        bail!("program not found: {}", program.display());
    }

    // If elevation was requested and we are not already elevated, re-launch this
    // launcher through a UAC prompt. The elevated instance then performs the
    // normal suspended-create + inject, so both it and the target share the same
    // integrity level and injection keeps working.
    if args.elevate && !rslocalehook_common::is_elevated() {
        let exe = std::env::current_exe().context("locating launcher executable")?;
        let params = build_relaunch_params(&args, &program);
        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let code = unsafe {
            rslocalehook_common::run_elevated(&exe.to_string_lossy(), &params, cwd.as_deref())
        }
        .context("re-launching elevated")?;
        std::process::exit(code as i32);
    }

    // Injection is same-bitness only. If the target is the opposite bitness to
    // this launcher, hand the whole job to the matching-bitness sibling launcher
    // deployed next to us (which injects the correct hook DLL).
    if let Some(target_is_64) = pe_is_64bit(&program) {
        if target_is_64 != rslocalehook_common::BUILD_IS_64BIT {
            let code = delegate_to_sibling(&args, &program, target_is_64)?;
            std::process::exit(code);
        }
    }

    let dll = hook_dll_path()?;

    let command_line = match args.args.as_deref() {
        Some(extra) if !extra.is_empty() => {
            format!("\"{}\" {}", program.display(), extra)
        }
        _ => format!("\"{}\"", program.display()),
    };

    let dll_str = dll.to_string_lossy().into_owned();
    // SAFETY: single-threaded here, so mutating the environment and spawning the
    // child process does not race with anything.
    let outcome = unsafe { rslocalehook_common::launch(&command_line, &dll_str, &config) }
        .context("launching target process")?;

    std::process::exit(outcome.exit_code as i32);
}

/// Builds the effective `no_hook` pattern list: the user's `--no-hook` values,
/// plus the built-in anti-cheat defaults unless `--hook-anticheat` was given.
fn effective_no_hook(args: &RunArgs) -> Vec<String> {
    let mut patterns = args.no_hook.clone();
    if !args.hook_anticheat {
        for &default in rslocalehook_common::DEFAULT_ANTICHEAT {
            if !patterns.iter().any(|p| p.eq_ignore_ascii_case(default)) {
                patterns.push(default.to_string());
            }
        }
    }
    patterns
}

/// Reconstructs the launcher's `run` argument vector (for re-invoking this or a
/// sibling launcher). The resolved absolute program path is used, and
/// `--elevate` is intentionally omitted so re-invocation never loops. The
/// built-in anti-cheat defaults are not re-emitted; the new instance re-derives
/// them itself from `--hook-anticheat` and the user's own `--no-hook` values.
fn relaunch_arg_vec(args: &RunArgs, program: &std::path::Path) -> Vec<String> {
    let mut parts = vec!["run".to_string(), program.to_string_lossy().into_owned()];
    parts.push("--nls".into());
    parts.push(args.nls.clone());
    if let Some(timezone) = &args.timezone {
        parts.push("--timezone".into());
        parts.push(timezone.clone());
    }
    if let Some(codepage) = args.codepage {
        parts.push("--codepage".into());
        parts.push(codepage.to_string());
    }
    if args.hookime {
        parts.push("--hookime".into());
    }
    if args.hooklcid {
        parts.push("--hooklcid".into());
    }
    for pattern in &args.no_hook {
        parts.push("--no-hook".into());
        parts.push(pattern.clone());
    }
    if args.hook_anticheat {
        parts.push("--hook-anticheat".into());
    }
    if let Some(extra) = &args.args {
        parts.push("--args".into());
        parts.push(extra.clone());
    }
    parts
}

/// Joins [`relaunch_arg_vec`] into a single, quoted command-line string for
/// `ShellExecuteExW` (which takes the parameters as one string).
fn build_relaunch_params(args: &RunArgs, program: &std::path::Path) -> String {
    relaunch_arg_vec(args, program)
        .iter()
        .map(|part| quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Wraps a value in double quotes if it contains characters that the command
/// line would otherwise split on.
fn quote(value: &str) -> String {
    if value.is_empty() || value.contains([' ', '\t', '"']) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Parses an LCID given in hexadecimal, with an optional `0x` prefix.
fn parse_lcid(value: &str) -> Result<u32> {
    let trimmed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    Ok(u32::from_str_radix(trimmed, 16)?)
}

/// Resolves the default ANSI code page for an LCID via `GetLocaleInfoW`.
fn ansi_codepage_for(lcid: u32) -> Option<u32> {
    let mut value: u32 = 0;
    // With LOCALE_RETURN_NUMBER the result is written as a DWORD into the
    // buffer, so cchData is the number of WCHARs that DWORD occupies.
    let written = unsafe {
        GetLocaleInfoW(
            lcid,
            LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
            &mut value as *mut u32 as *mut u16,
            (std::mem::size_of::<u32>() / std::mem::size_of::<u16>()) as i32,
        )
    };
    if written == 0 || value == 0 {
        None
    } else {
        Some(value)
    }
}

/// Computes the standard UTC offset (east-positive, in minutes) for an IANA
/// time zone, matching the original project's `Bias` convention.
fn bias_minutes(name: &str) -> Result<i32> {
    let tz: Tz = name
        .parse()
        .map_err(|e| anyhow::anyhow!("unknown time zone: {e}"))?;
    let offset = tz.offset_from_utc_datetime(&Utc::now().naive_utc());
    let minutes = offset.base_utc_offset().num_minutes();
    Ok(minutes as i32)
}

/// File name of the hook DLL that matches this launcher's bitness.
#[cfg(target_pointer_width = "64")]
const HOOK_DLL: &str = "rslocalehook_hook.dll";
#[cfg(target_pointer_width = "32")]
const HOOK_DLL: &str = "rslocalehook_hook32.dll";

/// File name of the opposite-bitness launcher used to handle mismatched targets.
#[cfg(target_pointer_width = "64")]
const SIBLING_LAUNCHER: &str = "rslocalehook32.exe";
#[cfg(target_pointer_width = "32")]
const SIBLING_LAUNCHER: &str = "rslocalehook.exe";

/// Locates the hook DLL (matching this launcher's bitness) next to the executable.
fn hook_dll_path() -> Result<std::path::PathBuf> {
    let dir = launcher_dir()?;
    let dll = dir.join(HOOK_DLL);
    if !dll.exists() {
        bail!("hook DLL not found next to the launcher: {}", dll.display());
    }
    Ok(dll)
}

/// Directory that contains this launcher executable.
fn launcher_dir() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("locating launcher executable")?;
    exe.parent()
        .map(std::path::Path::to_path_buf)
        .context("launcher executable has no parent directory")
}

/// Reads a PE file's machine field to decide its bitness. Returns `Some(true)`
/// for 64-bit (AMD64/ARM64), `Some(false)` for 32-bit (I386), and `None` when
/// the file is not a recognizable PE (e.g. a .NET "AnyCPU" image is reported by
/// its machine field and treated accordingly).
fn pe_is_64bit(path: &std::path::Path) -> Option<bool> {
    use std::io::{Read, Seek, SeekFrom};

    const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

    let mut file = std::fs::File::open(path).ok()?;
    let mut dos = [0u8; 0x40];
    file.read_exact(&mut dos).ok()?;
    if &dos[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as u64;
    file.seek(SeekFrom::Start(e_lfanew)).ok()?;
    let mut head = [0u8; 6]; // "PE\0\0" + machine (u16)
    file.read_exact(&mut head).ok()?;
    if &head[0..4] != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes([head[4], head[5]]);
    match machine {
        IMAGE_FILE_MACHINE_I386 => Some(false),
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => Some(true),
        _ => None,
    }
}

/// Hands the launch over to the opposite-bitness sibling launcher and returns
/// its exit code.
fn delegate_to_sibling(
    args: &RunArgs,
    program: &std::path::Path,
    target_is_64: bool,
) -> Result<i32> {
    let sibling = launcher_dir()?.join(SIBLING_LAUNCHER);
    if !sibling.exists() {
        bail!(
            "target is {}-bit but the matching launcher was not found: {}",
            if target_is_64 { "64" } else { "32" },
            sibling.display()
        );
    }
    let status = std::process::Command::new(&sibling)
        .args(relaunch_arg_vec(args, program))
        .status()
        .with_context(|| format!("running sibling launcher {}", sibling.display()))?;
    Ok(status.code().unwrap_or(1))
}

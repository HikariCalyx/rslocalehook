//! Shared code between the `rslocalehook` launcher and the injected hook DLL.
//!
//! This crate owns two concerns:
//!
//! * [`Config`] - the locale settings that the launcher passes to the hook DLL
//!   through environment variables (the child process inherits them).
//! * [`inject`] / [`launch`] - classic suspended-process DLL injection used both
//!   by the launcher and by the hook when the target spawns a child process.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED, FALSE, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess, GetExitCodeThread,
    IsWow64Process2, OpenProcessToken, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
    INFINITE, LPTHREAD_START_ROUTINE, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

/// Environment variable names used to hand the configuration to the hook DLL.
pub mod env {
    pub const CODEPAGE: &str = "RSLOCALEHOOK_CODEPAGE";
    pub const LCID: &str = "RSLOCALEHOOK_LCID";
    pub const BIAS: &str = "RSLOCALEHOOK_BIAS";
    pub const HOOK_IME: &str = "RSLOCALEHOOK_HOOKIME";
    pub const HOOK_LCID: &str = "RSLOCALEHOOK_HOOKLCID";
    /// Full path to the hook DLL, so a hooked child process can re-inject it.
    pub const DLL: &str = "RSLOCALEHOOK_DLL";
    /// Newline-separated substrings; child processes whose command line matches
    /// one are launched without injecting the hook DLL.
    pub const NO_HOOK: &str = "RSLOCALEHOOK_NOHOOK";
}

/// Separator used to pack the `no_hook` patterns into one environment variable.
/// A newline cannot appear in a normal executable path or name.
const NO_HOOK_SEPARATOR: char = '\n';

/// Case-insensitive substrings of well-known anti-cheat / DRM / packer modules
/// and their helper processes. By default the launcher adds these to the
/// `no_hook` list so that such code is neither injected into (as a child
/// process) nor affected by the API hooks (when it calls them itself). Entries
/// are deliberately distinctive to avoid matching ordinary system DLLs.
pub const DEFAULT_ANTICHEAT: &[&str] = &[
    // INCA nProtect GameGuard
    "gameguard",
    "gamemon",
    "npgg",
    "npprue",
    // Wellbia XIGNCODE3 / xHunter
    "xigncode",
    "xhunter",
    // AhnLab HackShield
    "hackshield",
    "hshield",
    "ehsvc",
    // Tencent TenProtect / Anti-Cheat Expert (ACE)
    "anticheatexpert",
    "ace-base",
    "ace-guard",
    "tenprotect",
    "tensafe",
    "tphelper",
    "qqprotect",
    // Epic EasyAntiCheat
    "easyanticheat",
    "eac_launcher",
    // BattlEye
    "battleye",
    "beservice",
    "beclient",
    "bedaisy",
    // Riot Vanguard
    "vgc",
    "vgk",
    "vgtray",
    // Even Balance PunkBuster
    "pnkbstr",
    // miHoYo mhyprot
    "mhyprot",
    // Denuvo Anti-Cheat
    "denuvo",
    // Game Protect Kit
    "sddyn",
    "sdictn",
    "sdgame",
    "gpk.",
    "gpe.",
    "gt",
    "gpkit",
    // Nexon Game Security
    "blackxchg",
    "blackcipher",
    "blackcall",
    "blackcat",
    "grap",
    "ngservice",
];

/// Locale emulation settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// ANSI code page reported to the target (e.g. 932 for Shift-JIS).
    pub codepage: u32,
    /// Locale identifier reported to the target (e.g. 0x0411 for ja-JP).
    pub lcid: u32,
    /// UTC offset east of Greenwich, in minutes (e.g. +540 for UTC+9).
    /// This matches the original project's `Bias` field; the time-zone hook
    /// negates it to produce the Win32 `TIME_ZONE_INFORMATION::Bias`.
    pub bias: i32,
    /// Whether to hook IME composition/candidate APIs.
    pub hook_ime: bool,
    /// Whether to hook window-class registration for LCID spoofing.
    pub hook_lcid: bool,
    /// Case-insensitive substrings. A child process whose application name or
    /// command line contains any of these is spawned without injection, so it
    /// (and anything it loads, e.g. GPK/anti-cheat modules) runs un-hooked.
    pub no_hook: Vec<String>,
}

impl Config {
    /// Publishes the configuration into the current process environment so that
    /// any child process (and the DLL loaded into it) inherits it.
    ///
    /// # Safety
    /// Mutates process-global environment state; must not race with other
    /// threads reading or writing the environment.
    pub unsafe fn publish_to_env(&self) {
        unsafe {
            std::env::set_var(env::CODEPAGE, self.codepage.to_string());
            std::env::set_var(env::LCID, self.lcid.to_string());
            std::env::set_var(env::BIAS, self.bias.to_string());
            std::env::set_var(env::HOOK_IME, bool_env(self.hook_ime));
            std::env::set_var(env::HOOK_LCID, bool_env(self.hook_lcid));
            std::env::set_var(
                env::NO_HOOK,
                self.no_hook.join(&NO_HOOK_SEPARATOR.to_string()),
            );
        }
    }

    /// Reads the configuration that the launcher published into the environment.
    /// Missing or malformed values fall back to passthrough defaults.
    pub fn from_env() -> Self {
        Config {
            codepage: read_u32(env::CODEPAGE).unwrap_or(0),
            lcid: read_u32(env::LCID).unwrap_or(0x0409),
            bias: std::env::var(env::BIAS)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            hook_ime: read_bool(env::HOOK_IME),
            hook_lcid: read_bool(env::HOOK_LCID),
            no_hook: std::env::var(env::NO_HOOK)
                .ok()
                .map(|value| {
                    value
                        .split(NO_HOOK_SEPARATOR)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// Returns whether a child process (identified by its application name
    /// and/or command line in `target`) should be launched without injecting
    /// the hook DLL, because `target` matches one of the `no_hook` patterns.
    pub fn should_skip_injection(&self, target: &str) -> bool {
        matches_any(&self.no_hook, target)
    }
}

/// Case-insensitive substring match of `text` against any non-empty pattern.
pub fn matches_any(patterns: &[String], text: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    patterns
        .iter()
        .filter(|p| !p.is_empty())
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

fn bool_env(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn read_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok()?.parse().ok()
}

fn read_bool(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1") | Ok("true"))
}

/// Encodes a string as a NUL-terminated UTF-16 buffer.
pub fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `true` when this crate was built as a 64-bit binary.
pub const BUILD_IS_64BIT: bool = cfg!(target_pointer_width = "64");

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

/// Returns whether `process` is a 32-bit (WOW64) process. Uses
/// `IsWow64Process2`, which reports the process machine as `I386` for a 32-bit
/// process and `UNKNOWN` (0) for one running natively.
///
/// # Safety
/// `process` must be a valid handle with query access.
pub unsafe fn process_is_32bit(process: *mut c_void) -> bool {
    unsafe {
        let mut process_machine: u16 = 0;
        let mut native_machine: u16 = 0;
        if IsWow64Process2(process, &mut process_machine, &mut native_machine) == 0 {
            return false;
        }
        process_machine == IMAGE_FILE_MACHINE_I386
    }
}

/// Injects `dll_path` into an already-created process by allocating the path in
/// the remote address space and running `LoadLibraryW` on a remote thread.
///
/// # Safety
/// `process` must be a valid process handle with rights to allocate memory,
/// write memory, and create a thread.
pub unsafe fn inject(process: *mut c_void, dll_path: &str) -> Result<()> {
    unsafe {
        // A DLL can only be loaded into a process of the same bitness. Refuse a
        // mismatch up front rather than spawning a doomed remote thread.
        if process_is_32bit(process) == BUILD_IS_64BIT {
            bail!("target process bitness does not match the hook DLL");
        }

        let wide = to_wide(dll_path);
        let bytes = wide.len() * std::mem::size_of::<u16>();

        let remote = VirtualAllocEx(
            process,
            null(),
            bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote.is_null() {
            bail!("VirtualAllocEx failed (error {})", GetLastError());
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            process,
            remote,
            wide.as_ptr().cast(),
            bytes,
            &mut written,
        ) == 0
        {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            bail!("WriteProcessMemory failed (error {})", GetLastError());
        }

        let kernel32 = GetModuleHandleW(to_wide("kernel32.dll").as_ptr());
        if kernel32.is_null() {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            bail!("GetModuleHandleW(kernel32.dll) failed");
        }
        let load_library = GetProcAddress(kernel32, c"LoadLibraryW".as_ptr().cast());
        let start: LPTHREAD_START_ROUTINE = std::mem::transmute(load_library);

        let thread = CreateRemoteThread(process, null(), 0, start, remote, 0, null_mut());
        if thread.is_null() {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            bail!("CreateRemoteThread failed (error {})", GetLastError());
        }

        WaitForSingleObject(thread, INFINITE);

        // The remote thread's exit code is the low 32 bits of the HMODULE
        // returned by LoadLibraryW; zero means the load failed.
        let mut module = 0u32;
        GetExitCodeThread(thread, &mut module);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(thread);

        if module == 0 {
            bail!("LoadLibraryW failed inside the target process");
        }
        Ok(())
    }
}

/// Result of launching and waiting for a target process.
pub struct LaunchOutcome {
    pub exit_code: u32,
}

/// Creates the target process suspended, injects the hook DLL, resumes it, and
/// waits for it to exit. `command_line` is the full command line (quoted exe
/// followed by its arguments). `config` is published to the environment first.
///
/// # Safety
/// Spawns a process and mutates the environment; callers must ensure no other
/// thread is concurrently modifying the environment.
pub unsafe fn launch(command_line: &str, dll_path: &str, config: &Config) -> Result<LaunchOutcome> {
    unsafe {
        config.publish_to_env();
        std::env::set_var(env::DLL, dll_path);

        let mut command = to_wide(command_line);
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut info: PROCESS_INFORMATION = std::mem::zeroed();

        let created = CreateProcessW(
            null(),
            command.as_mut_ptr(),
            null(),
            null(),
            FALSE,
            CREATE_SUSPENDED,
            null(),
            null(),
            &startup,
            &mut info,
        );
        if created == 0 {
            bail!("CreateProcessW failed (error {})", GetLastError());
        }

        let injected = inject(info.hProcess, dll_path).context("injecting hook DLL");
        if let Err(error) = injected {
            // Let the stillborn process run so it can be cleaned up by the OS.
            ResumeThread(info.hThread);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
            return Err(error);
        }

        ResumeThread(info.hThread);
        WaitForSingleObject(info.hProcess, INFINITE);

        let mut exit_code = 0u32;
        GetExitCodeProcess(info.hProcess, &mut exit_code);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);

        Ok(LaunchOutcome { exit_code })
    }
}

/// Returns whether the current process is running with an elevated token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Re-launches `exe` with the given `parameters` through a UAC elevation prompt
/// (the `runas` verb), waits for it to finish, and returns its exit code.
///
/// `directory` becomes the working directory of the elevated process.
///
/// # Safety
/// Spawns a process via the shell; callers must pass valid UTF-8 paths.
pub unsafe fn run_elevated(
    exe: &str,
    parameters: &str,
    directory: Option<&str>,
) -> Result<u32> {
    unsafe {
        let verb = to_wide("runas");
        let file = to_wide(exe);
        let params = to_wide(parameters);
        let dir = directory.map(to_wide);

        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.lpDirectory = dir.as_ref().map_or(null(), |d| d.as_ptr());
        info.nShow = 1; // SW_SHOWNORMAL

        if ShellExecuteExW(&mut info) == 0 {
            let error = GetLastError();
            if error == ERROR_CANCELLED {
                bail!("elevation was declined");
            }
            bail!("ShellExecuteExW(runas) failed (error {error})");
        }
        if info.hProcess.is_null() {
            bail!("the elevated process did not return a handle");
        }

        WaitForSingleObject(info.hProcess, INFINITE);
        let mut exit_code = 0u32;
        GetExitCodeProcess(info.hProcess, &mut exit_code);
        CloseHandle(info.hProcess);
        Ok(exit_code)
    }
}

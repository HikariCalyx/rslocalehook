//! `rslocalehook` hook DLL.
//!
//! When injected into a target process this DLL installs inline detours (via the
//! `retour` crate) over the ANSI/Unicode Win32 APIs so that the process behaves
//! as if it were running under a different system locale, ANSI code page and
//! time zone. It is a Rust reimplementation of the `LRHook` component of
//! Locale Remulator, driven by [`rslocalehook_common::Config`] read from the
//! environment that the launcher published.
//!
//! ## Excluding code from the hooks (`--no-hook`)
//!
//! Inline detours are process-global: the patched bytes of e.g. `GetACP` are
//! shared by every module in the process, so a hook cannot be removed for one
//! DLL only. Instead this DLL supports a *behavioural* bypass: modules whose
//! name matches a `no_hook` pattern (e.g. a packer / anti-cheat such as GPK)
//! have their address ranges recorded, and every hook checks its caller's
//! return address — if the call originates from an excluded module the original
//! API is invoked unchanged. The same patterns also suppress DLL injection into
//! matching child processes. (This does not hide the patched bytes from an
//! integrity scanner; it only stops our transformations from affecting that
//! module's own calls.)

#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use retour::RawDetour;
use rslocalehook_common::{env as cfg_env, matches_any, Config};

use windows_sys::core::{BOOL, PCSTR, PCWSTR, PSTR, PWSTR};
use windows_sys::Win32::Foundation::{HANDLE, HMODULE, HWND, LPARAM, LRESULT, RECT, TRUE, WPARAM};
use windows_sys::Win32::Globalization::GetCPInfo;
use windows_sys::Win32::Globalization::{
    lstrlenA, lstrlenW, GetACP, GetLocaleInfoA, GetLocaleInfoW, GetOEMCP, GetSystemDefaultLCID,
    GetSystemDefaultLangID, GetSystemDefaultUILanguage, GetThreadLocale, GetUserDefaultLCID,
    GetUserDefaultLangID, GetUserDefaultUILanguage, IsDBCSLeadByteEx, MultiByteToWideChar,
    WideCharToMultiByte, CPINFO, CP_UTF7,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontA, CreateFontIndirectA, CreateFontIndirectW, CreateFontW, DrawTextExA, DrawTextExW,
    DRAWTEXTPARAMS, HDC, HFONT, LF_FACESIZE, LOGFONTA, LOGFONTW,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryA, CreateDirectoryW, CreateFileA, CreateFileW,
};
use windows_sys::Win32::System::Console::{GetConsoleCP, GetConsoleOutputCP};
use windows_sys::Win32::System::DataExchange::{GetClipboardData, SetClipboardData};
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, LoadLibraryExA, LoadLibraryExW,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GHND};
use windows_sys::Win32::System::Ole::{CF_TEXT, CF_UNICODETEXT};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::{
    CreateProcessA, CreateProcessW, GetCurrentProcess, ResumeThread, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW,
};
use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
use windows_sys::Win32::UI::Input::Ime::{ImmGetCompositionStringA, ImmGetCompositionStringW, HIMC};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CharNextExA, CharPrevExA, CreateWindowExA, CreateWindowExW, MessageBoxA, MessageBoxW,
    SendMessageA, SendMessageW, CB_ADDSTRING, CB_DIR, CB_FINDSTRING, CB_FINDSTRINGEXACT,
    CB_INSERTSTRING, CB_SELECTSTRING, LB_ADDSTRING, LB_DIR, LB_FINDSTRING, LB_FINDSTRINGEXACT,
    LB_INSERTSTRING, LB_SELECTSTRING, WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT, WM_SETTINGCHANGE,
};
use windows_sys::Win32::UI::Controls::EM_REPLACESEL;

const TIME_ZONE_ID_INVALID: u32 = 0xFFFF_FFFF;
const MAX_PATH: usize = 260;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static CONFIG: OnceLock<Config> = OnceLock::new();
static DLL_PATH: OnceLock<Option<String>> = OnceLock::new();
/// The process's real ANSI code page, captured before any hook is installed.
static ORIGINAL_ACP: AtomicU32 = AtomicU32::new(0);
/// Keeps every installed detour alive for the lifetime of the process.
static DETOURS: OnceLock<Mutex<Vec<RawDetour>>> = OnceLock::new();

/// `[start, end)` address ranges of modules excluded from the hooks.
static EXCLUDED_RANGES: OnceLock<Mutex<Vec<(usize, usize)>>> = OnceLock::new();
/// Fast gate: stays `false` (and makes the caller check a single atomic load)
/// until at least one excluded module is actually present in the process.
static EXCLUSIONS_ACTIVE: AtomicBool = AtomicBool::new(false);

fn config() -> &'static Config {
    CONFIG.get_or_init(Config::from_env)
}

fn dll_path() -> Option<&'static str> {
    DLL_PATH
        .get_or_init(|| std::env::var(cfg_env::DLL).ok())
        .as_deref()
}

fn excluded_ranges() -> &'static Mutex<Vec<(usize, usize)>> {
    EXCLUDED_RANGES.get_or_init(|| Mutex::new(Vec::new()))
}

// Trampolines (addresses of the original, un-hooked functions). Every hook
// stores its trampoline so that the caller-bypass can invoke the original.
static ORIG_GET_ACP: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_OEMCP: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_CONSOLE_CP: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_CONSOLE_OUTPUT_CP: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_CP_INFO: AtomicUsize = AtomicUsize::new(0);
static ORIG_MB2WC: AtomicUsize = AtomicUsize::new(0);
static ORIG_WC2MB: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_THREAD_LOCALE: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_SYS_LCID: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_USER_LCID: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_SYS_UILANG: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_USER_UILANG: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_SYS_LANGID: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_USER_LANGID: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_LOCALE_INFO_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_LOCALE_INFO_W: AtomicUsize = AtomicUsize::new(0);
static ORIG_IS_DBCS: AtomicUsize = AtomicUsize::new(0);
static ORIG_CHAR_NEXT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CHAR_PREV: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_TZ: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_WINDOW_EX_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_MESSAGE_BOX_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_SEND_MESSAGE_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_DRAW_TEXT_EX_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_FONT_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_FONT_INDIRECT_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_GET_CLIPBOARD: AtomicUsize = AtomicUsize::new(0);
static ORIG_SET_CLIPBOARD: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_DIRECTORY_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_FILE_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_PROCESS_W: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_PROCESS_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_IMM_COMP_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_LOAD_LIBRARY_EX_W: AtomicUsize = AtomicUsize::new(0);
static ORIG_LOAD_LIBRARY_EX_A: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Function pointer type aliases
// ---------------------------------------------------------------------------

type FnRetU32 = unsafe extern "system" fn() -> u32;
type FnRetU16 = unsafe extern "system" fn() -> u16;
type FnGetCpInfo = unsafe extern "system" fn(u32, *mut CPINFO) -> BOOL;
type FnMb2Wc = unsafe extern "system" fn(u32, u32, PCSTR, i32, PWSTR, i32) -> i32;
type FnWc2Mb = unsafe extern "system" fn(u32, u32, PCWSTR, i32, PSTR, i32, PCSTR, *mut BOOL) -> i32;
type FnGetLocaleInfoA = unsafe extern "system" fn(u32, u32, PSTR, i32) -> i32;
type FnGetLocaleInfoW = unsafe extern "system" fn(u32, u32, PWSTR, i32) -> i32;
type FnIsDbcs = unsafe extern "system" fn(u32, u8) -> BOOL;
type FnCharNextExA = unsafe extern "system" fn(u16, PCSTR, u32) -> PSTR;
type FnCharPrevExA = unsafe extern "system" fn(u16, PCSTR, PCSTR, u32) -> PSTR;
type FnGetTz = unsafe extern "system" fn(*mut TIME_ZONE_INFORMATION) -> u32;
type FnCreateWindowExA = unsafe extern "system" fn(
    u32,
    PCSTR,
    PCSTR,
    u32,
    i32,
    i32,
    i32,
    i32,
    HWND,
    *mut c_void,
    *mut c_void,
    *const c_void,
) -> HWND;
type FnMessageBoxA = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
type FnSendMessageA = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;
type FnDrawTextExA =
    unsafe extern "system" fn(HDC, PSTR, i32, *mut RECT, u32, *const DRAWTEXTPARAMS) -> i32;
type FnCreateFontA = unsafe extern "system" fn(
    i32,
    i32,
    i32,
    i32,
    i32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    PCSTR,
) -> HFONT;
type FnCreateFontIndirectA = unsafe extern "system" fn(*const LOGFONTA) -> HFONT;
type FnGetClipboard = unsafe extern "system" fn(u32) -> HANDLE;
type FnSetClipboard = unsafe extern "system" fn(u32, HANDLE) -> HANDLE;
type FnCreateDirectoryA = unsafe extern "system" fn(PCSTR, *const SECURITY_ATTRIBUTES) -> BOOL;
type FnCreateFileA =
    unsafe extern "system" fn(PCSTR, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE) -> HANDLE;
type FnImmGetCompositionStringA = unsafe extern "system" fn(HIMC, u32, *mut c_void, u32) -> i32;
type FnLoadLibraryExW = unsafe extern "system" fn(PCWSTR, HANDLE, u32) -> HMODULE;
type FnLoadLibraryExA = unsafe extern "system" fn(PCSTR, HANDLE, u32) -> HMODULE;
type FnCreateProcessW = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    u32,
    *const c_void,
    PCWSTR,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;
type FnCreateProcessA = unsafe extern "system" fn(
    PCSTR,
    PSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    u32,
    *const c_void,
    PCSTR,
    *const STARTUPINFOA,
    *mut PROCESS_INFORMATION,
) -> BOOL;

macro_rules! orig {
    ($cell:ident, $ty:ty) => {
        core::mem::transmute::<usize, $ty>($cell.load(Ordering::Relaxed))
    };
}

// ---------------------------------------------------------------------------
// Caller-based bypass for excluded modules
// ---------------------------------------------------------------------------

/// Records the address range of `module` if its file name matches a `no_hook`
/// pattern, so that calls originating from it are passed through un-hooked.
unsafe fn consider_module(module: HMODULE) {
    if module.is_null() {
        return;
    }
    let patterns = &config().no_hook;
    if patterns.is_empty() {
        return;
    }

    let mut name = [0u16; MAX_PATH];
    let len = unsafe { GetModuleFileNameW(module, name.as_mut_ptr(), name.len() as u32) };
    if len == 0 {
        return;
    }
    let file = String::from_utf16_lossy(&name[..len as usize]);
    if !matches_any(patterns, &file) {
        return;
    }

    let mut info = MODULEINFO {
        lpBaseOfDll: null_mut(),
        SizeOfImage: 0,
        EntryPoint: null_mut(),
    };
    let ok = unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            module,
            &mut info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
    };
    if ok == 0 || info.lpBaseOfDll.is_null() || info.SizeOfImage == 0 {
        return;
    }

    let start = info.lpBaseOfDll as usize;
    let end = start + info.SizeOfImage as usize;
    if let Ok(mut ranges) = excluded_ranges().lock() {
        if !ranges.iter().any(|&(s, e)| s == start && e == end) {
            ranges.push((start, end));
        }
    }
    EXCLUSIONS_ACTIVE.store(true, Ordering::Relaxed);
}

/// Scans every currently loaded module and records the excluded ones.
unsafe fn scan_loaded_modules() {
    if config().no_hook.is_empty() {
        return;
    }
    let process = unsafe { GetCurrentProcess() };
    let mut needed = 0u32;
    unsafe { EnumProcessModules(process, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return;
    }
    let count = needed as usize / std::mem::size_of::<HMODULE>();
    let mut modules: Vec<HMODULE> = vec![null_mut(); count];
    let ok = unsafe {
        EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return;
    }
    for module in modules {
        unsafe { consider_module(module) };
    }
}

/// Returns whether the function that called the current hook lives inside an
/// excluded module. Kept out-of-line so the stack depth seen by
/// `RtlCaptureStackBackTrace` is deterministic.
#[inline(never)]
fn caller_excluded() -> bool {
    if !EXCLUSIONS_ACTIVE.load(Ordering::Relaxed) {
        return false;
    }
    // Stack (newest first): caller_excluded <- hook_fn <- real caller.
    // Skip the first two frames to land on the real caller's return address.
    let mut frame: *mut c_void = null_mut();
    let captured = unsafe { RtlCaptureStackBackTrace(2, 1, &mut frame, null_mut()) };
    if captured < 1 {
        return false;
    }
    let address = frame as usize;
    excluded_ranges()
        .lock()
        .map(|ranges| ranges.iter().any(|&(s, e)| address >= s && address < e))
        .unwrap_or(false)
}

/// Shorthand: `bypass!(CELL, FnType, args...)` returns the original result when
/// the caller is excluded. Placed at the top of every transforming hook.
macro_rules! bypass {
    ($cell:ident, $ty:ty, $($arg:expr),* $(,)?) => {
        if caller_excluded() {
            let original = unsafe { orig!($cell, $ty) };
            return unsafe { original($($arg),*) };
        }
    };
}

// ---------------------------------------------------------------------------
// String conversion helpers (use the trampolines to avoid re-entering hooks)
// ---------------------------------------------------------------------------

unsafe fn ansi_to_wide(ptr: PCSTR, code_page: u32) -> Option<Vec<u16>> {
    if ptr.is_null() {
        return None;
    }
    let len = unsafe { lstrlenA(ptr) };
    if len <= 0 {
        return Some(vec![0u16]);
    }
    let mut buf = vec![0u16; len as usize + 1];
    let mb2wc = unsafe { orig!(ORIG_MB2WC, FnMb2Wc) };
    let written = unsafe { mb2wc(code_page, 0, ptr, len, buf.as_mut_ptr(), len + 1) };
    let written = written.max(0) as usize;
    buf[written] = 0;
    buf.truncate(written + 1);
    Some(buf)
}

unsafe fn wide_to_ansi(ptr: PCWSTR, code_page: u32) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let len = unsafe { lstrlenW(ptr) };
    if len <= 0 {
        return Some(vec![0u8]);
    }
    let cap = (len as usize + 1) * 2;
    let mut buf = vec![0u8; cap];
    let wc2mb = unsafe { orig!(ORIG_WC2MB, FnWc2Mb) };
    let written =
        unsafe { wc2mb(code_page, 0, ptr, len, buf.as_mut_ptr(), cap as i32, null(), null_mut()) };
    let written = written.max(0) as usize;
    buf[written] = 0;
    buf.truncate(written + 1);
    Some(buf)
}

unsafe fn wide_ptr_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = unsafe { lstrlenW(ptr) }.max(0) as usize;
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

unsafe fn ansi_ptr_to_string(ptr: PCSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let len = unsafe { lstrlenA(ptr) }.max(0) as usize;
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(slice).into_owned()
}

// ---------------------------------------------------------------------------
// Code page hooks
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_get_acp() -> u32 {
    bypass!(ORIG_GET_ACP, FnRetU32,);
    config().codepage
}
unsafe extern "system" fn hook_get_oemcp() -> u32 {
    bypass!(ORIG_GET_OEMCP, FnRetU32,);
    config().codepage
}
unsafe extern "system" fn hook_get_console_cp() -> u32 {
    bypass!(ORIG_GET_CONSOLE_CP, FnRetU32,);
    config().codepage
}
unsafe extern "system" fn hook_get_console_output_cp() -> u32 {
    bypass!(ORIG_GET_CONSOLE_OUTPUT_CP, FnRetU32,);
    config().codepage
}

unsafe extern "system" fn hook_get_cp_info(_code_page: u32, cp_info: *mut CPINFO) -> BOOL {
    bypass!(ORIG_GET_CP_INFO, FnGetCpInfo, _code_page, cp_info);
    let orig = unsafe { orig!(ORIG_GET_CP_INFO, FnGetCpInfo) };
    unsafe { orig(config().codepage, cp_info) }
}

unsafe extern "system" fn hook_mb2wc(
    code_page: u32,
    flags: u32,
    mb: PCSTR,
    cb: i32,
    wc: PWSTR,
    cch: i32,
) -> i32 {
    bypass!(ORIG_MB2WC, FnMb2Wc, code_page, flags, mb, cb, wc, cch);
    let code_page = if code_page >= CP_UTF7 {
        code_page
    } else {
        config().codepage
    };
    let orig = unsafe { orig!(ORIG_MB2WC, FnMb2Wc) };
    unsafe { orig(code_page, flags, mb, cb, wc, cch) }
}

unsafe extern "system" fn hook_wc2mb(
    code_page: u32,
    flags: u32,
    wc: PCWSTR,
    cch: i32,
    mb: PSTR,
    cb: i32,
    default_char: PCSTR,
    used_default: *mut BOOL,
) -> i32 {
    bypass!(
        ORIG_WC2MB,
        FnWc2Mb,
        code_page,
        flags,
        wc,
        cch,
        mb,
        cb,
        default_char,
        used_default
    );
    let code_page = if code_page >= CP_UTF7 {
        code_page
    } else {
        config().codepage
    };
    let orig = unsafe { orig!(ORIG_WC2MB, FnWc2Mb) };
    unsafe { orig(code_page, flags, wc, cch, mb, cb, default_char, used_default) }
}

// ---------------------------------------------------------------------------
// Locale id hooks
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_get_thread_locale() -> u32 {
    bypass!(ORIG_GET_THREAD_LOCALE, FnRetU32,);
    config().lcid
}
unsafe extern "system" fn hook_get_system_default_lcid() -> u32 {
    bypass!(ORIG_GET_SYS_LCID, FnRetU32,);
    config().lcid
}
unsafe extern "system" fn hook_get_user_default_lcid() -> u32 {
    bypass!(ORIG_GET_USER_LCID, FnRetU32,);
    config().lcid
}
unsafe extern "system" fn hook_get_system_default_ui_language() -> u16 {
    bypass!(ORIG_GET_SYS_UILANG, FnRetU16,);
    config().lcid as u16
}
unsafe extern "system" fn hook_get_user_default_ui_language() -> u16 {
    bypass!(ORIG_GET_USER_UILANG, FnRetU16,);
    config().lcid as u16
}
unsafe extern "system" fn hook_get_system_default_langid() -> u16 {
    bypass!(ORIG_GET_SYS_LANGID, FnRetU16,);
    config().lcid as u16
}
unsafe extern "system" fn hook_get_user_default_langid() -> u16 {
    bypass!(ORIG_GET_USER_LANGID, FnRetU16,);
    config().lcid as u16
}

unsafe extern "system" fn hook_get_locale_info_a(
    locale: u32,
    lc_type: u32,
    data: PSTR,
    cch: i32,
) -> i32 {
    bypass!(ORIG_GET_LOCALE_INFO_A, FnGetLocaleInfoA, locale, lc_type, data, cch);
    let orig = unsafe { orig!(ORIG_GET_LOCALE_INFO_A, FnGetLocaleInfoA) };
    unsafe { orig(config().lcid, lc_type, data, cch) }
}

unsafe extern "system" fn hook_get_locale_info_w(
    locale: u32,
    lc_type: u32,
    data: PWSTR,
    cch: i32,
) -> i32 {
    bypass!(ORIG_GET_LOCALE_INFO_W, FnGetLocaleInfoW, locale, lc_type, data, cch);
    let orig = unsafe { orig!(ORIG_GET_LOCALE_INFO_W, FnGetLocaleInfoW) };
    unsafe { orig(config().lcid, lc_type, data, cch) }
}

// ---------------------------------------------------------------------------
// DBCS / character traversal hooks
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_is_dbcs_lead_byte_ex(code_page: u32, test: u8) -> BOOL {
    bypass!(ORIG_IS_DBCS, FnIsDbcs, code_page, test);
    let code_page = if code_page >= CP_UTF7 {
        code_page
    } else {
        config().codepage
    };
    let orig = unsafe { orig!(ORIG_IS_DBCS, FnIsDbcs) };
    unsafe { orig(code_page, test) }
}

unsafe extern "system" fn hook_char_next_ex_a(code_page: u16, current: PCSTR, flags: u32) -> PSTR {
    bypass!(ORIG_CHAR_NEXT, FnCharNextExA, code_page, current, flags);
    let code_page = if code_page as u32 >= CP_UTF7 {
        code_page
    } else {
        config().codepage as u16
    };
    let orig = unsafe { orig!(ORIG_CHAR_NEXT, FnCharNextExA) };
    unsafe { orig(code_page, current, flags) }
}

unsafe extern "system" fn hook_char_prev_ex_a(
    code_page: u16,
    start: PCSTR,
    current: PCSTR,
    flags: u32,
) -> PSTR {
    bypass!(ORIG_CHAR_PREV, FnCharPrevExA, code_page, start, current, flags);
    let code_page = if code_page as u32 >= CP_UTF7 {
        code_page
    } else {
        config().codepage as u16
    };
    let orig = unsafe { orig!(ORIG_CHAR_PREV, FnCharPrevExA) };
    unsafe { orig(code_page, start, current, flags) }
}

// ---------------------------------------------------------------------------
// Time zone hook
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_get_time_zone_information(tz: *mut TIME_ZONE_INFORMATION) -> u32 {
    bypass!(ORIG_GET_TZ, FnGetTz, tz);
    let orig = unsafe { orig!(ORIG_GET_TZ, FnGetTz) };
    let result = unsafe { orig(tz) };
    if result != TIME_ZONE_ID_INVALID && !tz.is_null() {
        unsafe { (*tz).Bias = -config().bias };
    }
    result
}

// ---------------------------------------------------------------------------
// Window / message text hooks
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_create_window_ex_a(
    ex_style: u32,
    class_name: PCSTR,
    window_name: PCSTR,
    style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: *mut c_void,
    instance: *mut c_void,
    param: *const c_void,
) -> HWND {
    bypass!(
        ORIG_CREATE_WINDOW_EX_A,
        FnCreateWindowExA,
        ex_style,
        class_name,
        window_name,
        style,
        x,
        y,
        width,
        height,
        parent,
        menu,
        instance,
        param
    );
    let cp = config().codepage;

    let class_is_atom = (class_name as usize) < 0x10000;
    let class_wide = if class_is_atom {
        None
    } else {
        unsafe { ansi_to_wide(class_name, cp) }
    };
    let window_wide = unsafe { ansi_to_wide(window_name, cp) };

    let class_ptr: PCWSTR = if class_is_atom {
        class_name as PCWSTR
    } else {
        class_wide.as_ref().map_or(null(), |v| v.as_ptr())
    };
    let window_ptr: PCWSTR = window_wide.as_ref().map_or(null(), |v| v.as_ptr());

    unsafe {
        CreateWindowExW(
            ex_style, class_ptr, window_ptr, style, x, y, width, height, parent, menu, instance,
            param,
        )
    }
}

unsafe extern "system" fn hook_message_box_a(
    hwnd: HWND,
    text: PCSTR,
    caption: PCSTR,
    style: u32,
) -> i32 {
    bypass!(ORIG_MESSAGE_BOX_A, FnMessageBoxA, hwnd, text, caption, style);
    let cp = config().codepage;
    let text_w = unsafe { ansi_to_wide(text, cp) };
    let caption_w = unsafe { ansi_to_wide(caption, cp) };
    unsafe {
        MessageBoxW(
            hwnd,
            text_w.as_ref().map_or(null(), |v| v.as_ptr()),
            caption_w.as_ref().map_or(null(), |v| v.as_ptr()),
            style,
        )
    }
}

unsafe extern "system" fn hook_send_message_a(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    bypass!(ORIG_SEND_MESSAGE_A, FnSendMessageA, hwnd, msg, wparam, lparam);
    let cp = config().codepage;
    match msg {
        WM_SETTEXT | WM_SETTINGCHANGE | EM_REPLACESEL | CB_DIR | LB_DIR | CB_ADDSTRING
        | CB_INSERTSTRING | CB_FINDSTRING | CB_SELECTSTRING | CB_FINDSTRINGEXACT | LB_ADDSTRING
        | LB_INSERTSTRING | LB_SELECTSTRING | LB_FINDSTRING | LB_FINDSTRINGEXACT => {
            let wide = unsafe { ansi_to_wide(lparam as PCSTR, cp) };
            match wide {
                Some(buf) => unsafe { SendMessageW(hwnd, msg, wparam, buf.as_ptr() as LPARAM) },
                None => unsafe { SendMessageW(hwnd, msg, wparam, lparam) },
            }
        }
        WM_GETTEXT => unsafe { ansi_out_string(hwnd, msg, wparam, lparam, cp) },
        WM_GETTEXTLENGTH => unsafe { ansi_get_text_length(hwnd, cp) },
        _ => {
            let orig = unsafe { orig!(ORIG_SEND_MESSAGE_A, FnSendMessageA) };
            unsafe { orig(hwnd, msg, wparam, lparam) }
        }
    }
}

unsafe fn ansi_out_string(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    cp: u32,
) -> LRESULT {
    let ansi_buf = lparam as *mut u8;
    let ansi_max = wparam as i32;
    if ansi_buf.is_null() || ansi_max <= 0 {
        return 0;
    }

    let wlen = unsafe { SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) };
    if wlen <= 0 {
        unsafe { *ansi_buf = 0 };
        return 0;
    }
    let mut wbuf = vec![0u16; wlen as usize + 1];
    let got = unsafe { SendMessageW(hwnd, msg, wbuf.len(), wbuf.as_mut_ptr() as LPARAM) };
    if got <= 0 {
        unsafe { *ansi_buf = 0 };
        return 0;
    }
    let wc2mb = unsafe { orig!(ORIG_WC2MB, FnWc2Mb) };
    let n = unsafe {
        wc2mb(cp, 0, wbuf.as_ptr(), got as i32, ansi_buf, ansi_max, null(), null_mut())
    };
    let n = n.max(0);
    if n < ansi_max {
        unsafe { *ansi_buf.add(n as usize) = 0 };
    }
    n as LRESULT
}

unsafe fn ansi_get_text_length(hwnd: HWND, cp: u32) -> LRESULT {
    let wlen = unsafe { SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) };
    if wlen <= 0 {
        return wlen;
    }
    let mut wbuf = vec![0u16; wlen as usize + 1];
    let got = unsafe { SendMessageW(hwnd, WM_GETTEXT, wbuf.len(), wbuf.as_mut_ptr() as LPARAM) };
    if got <= 0 {
        return 0;
    }
    let wc2mb = unsafe { orig!(ORIG_WC2MB, FnWc2Mb) };
    let bytes =
        unsafe { wc2mb(cp, 0, wbuf.as_ptr(), got as i32, null_mut(), 0, null(), null_mut()) };
    bytes.max(0) as LRESULT
}

unsafe extern "system" fn hook_draw_text_ex_a(
    hdc: HDC,
    text: PSTR,
    count: i32,
    rect: *mut RECT,
    format: u32,
    params: *const DRAWTEXTPARAMS,
) -> i32 {
    bypass!(ORIG_DRAW_TEXT_EX_A, FnDrawTextExA, hdc, text, count, rect, format, params);
    let cp = config().codepage;
    if let Some(mut wide) = unsafe { ansi_to_wide(text, cp) } {
        let wlen = unsafe { lstrlenW(wide.as_ptr()) };
        return unsafe { DrawTextExW(hdc, wide.as_mut_ptr(), wlen, rect, format, params) };
    }
    let orig = unsafe { orig!(ORIG_DRAW_TEXT_EX_A, FnDrawTextExA) };
    unsafe { orig(hdc, text, count, rect, format, params) }
}

// ---------------------------------------------------------------------------
// Font hooks
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_create_font_a(
    height: i32,
    width: i32,
    escapement: i32,
    orientation: i32,
    weight: i32,
    italic: u32,
    underline: u32,
    strike_out: u32,
    char_set: u32,
    out_precision: u32,
    clip_precision: u32,
    quality: u32,
    pitch_and_family: u32,
    face_name: PCSTR,
) -> HFONT {
    bypass!(
        ORIG_CREATE_FONT_A,
        FnCreateFontA,
        height,
        width,
        escapement,
        orientation,
        weight,
        italic,
        underline,
        strike_out,
        char_set,
        out_precision,
        clip_precision,
        quality,
        pitch_and_family,
        face_name
    );
    let cp = config().codepage;
    let face = unsafe { ansi_to_wide(face_name, cp) };
    unsafe {
        CreateFontW(
            height,
            width,
            escapement,
            orientation,
            weight,
            italic,
            underline,
            strike_out,
            char_set,
            out_precision,
            clip_precision,
            quality,
            pitch_and_family,
            face.as_ref().map_or(null(), |v| v.as_ptr()),
        )
    }
}

unsafe extern "system" fn hook_create_font_indirect_a(logfont: *const LOGFONTA) -> HFONT {
    bypass!(ORIG_CREATE_FONT_INDIRECT_A, FnCreateFontIndirectA, logfont);
    if logfont.is_null() {
        return null_mut();
    }
    let cp = config().codepage;
    let src = unsafe { &*logfont };

    let mut dst: LOGFONTW = LOGFONTW {
        lfHeight: src.lfHeight,
        lfWidth: src.lfWidth,
        lfEscapement: src.lfEscapement,
        lfOrientation: src.lfOrientation,
        lfWeight: src.lfWeight,
        lfItalic: src.lfItalic,
        lfUnderline: src.lfUnderline,
        lfStrikeOut: src.lfStrikeOut,
        lfCharSet: src.lfCharSet,
        lfOutPrecision: src.lfOutPrecision,
        lfClipPrecision: src.lfClipPrecision,
        lfQuality: src.lfQuality,
        lfPitchAndFamily: src.lfPitchAndFamily,
        lfFaceName: [0u16; LF_FACESIZE as usize],
    };

    let mb2wc = unsafe { orig!(ORIG_MB2WC, FnMb2Wc) };
    unsafe {
        mb2wc(
            cp,
            0,
            src.lfFaceName.as_ptr() as PCSTR,
            -1,
            dst.lfFaceName.as_mut_ptr(),
            LF_FACESIZE as i32,
        );
    }

    unsafe { CreateFontIndirectW(&dst) }
}

// ---------------------------------------------------------------------------
// Clipboard hooks
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_get_clipboard_data(format: u32) -> HANDLE {
    bypass!(ORIG_GET_CLIPBOARD, FnGetClipboard, format);
    let orig = unsafe { orig!(ORIG_GET_CLIPBOARD, FnGetClipboard) };
    if format == CF_TEXT as u32 {
        let wide_handle = unsafe { orig(CF_UNICODETEXT as u32) };
        if !wide_handle.is_null() {
            let wide = unsafe { GlobalLock(wide_handle) } as PCWSTR;
            if !wide.is_null() {
                let converted = unsafe { wide_to_ansi(wide, config().codepage) };
                unsafe { GlobalUnlock(wide_handle) };
                if let Some(ansi) = converted {
                    let global = unsafe { GlobalAlloc(GHND, ansi.len()) };
                    if !global.is_null() {
                        let dst = unsafe { GlobalLock(global) } as *mut u8;
                        if !dst.is_null() {
                            unsafe {
                                std::ptr::copy_nonoverlapping(ansi.as_ptr(), dst, ansi.len());
                                GlobalUnlock(global);
                            }
                            return global;
                        }
                    }
                }
            }
        }
    }
    unsafe { orig(format) }
}

unsafe extern "system" fn hook_set_clipboard_data(format: u32, mem: HANDLE) -> HANDLE {
    bypass!(ORIG_SET_CLIPBOARD, FnSetClipboard, format, mem);
    let orig = unsafe { orig!(ORIG_SET_CLIPBOARD, FnSetClipboard) };
    if format == CF_TEXT as u32 && !mem.is_null() {
        let ansi = unsafe { GlobalLock(mem) } as PCSTR;
        if !ansi.is_null() {
            let converted = unsafe { ansi_to_wide(ansi, config().codepage) };
            unsafe { GlobalUnlock(mem) };
            if let Some(wide) = converted {
                let bytes = wide.len() * 2;
                let global = unsafe { GlobalAlloc(GHND, bytes) };
                if !global.is_null() {
                    let dst = unsafe { GlobalLock(global) } as *mut u16;
                    if !dst.is_null() {
                        unsafe {
                            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
                            GlobalUnlock(global);
                        }
                        return unsafe { orig(CF_UNICODETEXT as u32, global) };
                    }
                }
            }
        }
    }
    unsafe { orig(format, mem) }
}

// ---------------------------------------------------------------------------
// File-system hooks (ANSI paths are in the emulated code page)
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_create_directory_a(
    path: PCSTR,
    security: *const SECURITY_ATTRIBUTES,
) -> BOOL {
    bypass!(ORIG_CREATE_DIRECTORY_A, FnCreateDirectoryA, path, security);
    let cp = config().codepage;
    match unsafe { ansi_to_wide(path, cp) } {
        Some(wide) => unsafe { CreateDirectoryW(wide.as_ptr(), security) },
        None => unsafe { CreateDirectoryW(null(), security) },
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_create_file_a(
    file_name: PCSTR,
    desired_access: u32,
    share_mode: u32,
    security: *const SECURITY_ATTRIBUTES,
    creation_disposition: u32,
    flags_and_attributes: u32,
    template_file: HANDLE,
) -> HANDLE {
    bypass!(
        ORIG_CREATE_FILE_A,
        FnCreateFileA,
        file_name,
        desired_access,
        share_mode,
        security,
        creation_disposition,
        flags_and_attributes,
        template_file
    );
    let cp = config().codepage;
    let wide = unsafe { ansi_to_wide(file_name, cp) };
    unsafe {
        CreateFileW(
            wide.as_ref().map_or(null(), |v| v.as_ptr()),
            desired_access,
            share_mode,
            security,
            creation_disposition,
            flags_and_attributes,
            template_file,
        )
    }
}

// ---------------------------------------------------------------------------
// Child-process propagation hooks
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_create_process_w(
    app: PCWSTR,
    cmd: PWSTR,
    proc_attrs: *const SECURITY_ATTRIBUTES,
    thread_attrs: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    environment: *const c_void,
    cwd: PCWSTR,
    startup: *const STARTUPINFOW,
    info: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig = unsafe { orig!(ORIG_CREATE_PROCESS_W, FnCreateProcessW) };

    // Pass through unchanged when the caller is excluded, or when the child
    // itself matches a no-hook pattern (do not inject into it).
    let mut target = unsafe { wide_ptr_to_string(app) };
    if !target.is_empty() {
        target.push(' ');
    }
    target.push_str(&unsafe { wide_ptr_to_string(cmd as PCWSTR) });
    if caller_excluded() || config().should_skip_injection(&target) {
        return unsafe {
            orig(
                app, cmd, proc_attrs, thread_attrs, inherit, flags, environment, cwd, startup, info,
            )
        };
    }

    let created = unsafe {
        orig(
            app,
            cmd,
            proc_attrs,
            thread_attrs,
            inherit,
            flags | CREATE_SUSPENDED,
            environment,
            cwd,
            startup,
            info,
        )
    };
    if created == 0 || info.is_null() {
        return created;
    }
    unsafe { propagate_and_resume(info, flags) };
    TRUE
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_create_process_a(
    app: PCSTR,
    cmd: PSTR,
    proc_attrs: *const SECURITY_ATTRIBUTES,
    thread_attrs: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    environment: *const c_void,
    cwd: PCSTR,
    startup: *const STARTUPINFOA,
    info: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig = unsafe { orig!(ORIG_CREATE_PROCESS_A, FnCreateProcessA) };

    let mut target = unsafe { ansi_ptr_to_string(app) };
    if !target.is_empty() {
        target.push(' ');
    }
    target.push_str(&unsafe { ansi_ptr_to_string(cmd as PCSTR) });
    if caller_excluded() || config().should_skip_injection(&target) {
        return unsafe {
            orig(
                app, cmd, proc_attrs, thread_attrs, inherit, flags, environment, cwd, startup, info,
            )
        };
    }

    let created = unsafe {
        orig(
            app,
            cmd,
            proc_attrs,
            thread_attrs,
            inherit,
            flags | CREATE_SUSPENDED,
            environment,
            cwd,
            startup,
            info,
        )
    };
    if created == 0 || info.is_null() {
        return created;
    }
    unsafe { propagate_and_resume(info, flags) };
    TRUE
}

/// Injects the hook DLL into a freshly created (suspended) child and resumes it
/// unless the caller originally asked for a suspended process.
unsafe fn propagate_and_resume(info: *mut PROCESS_INFORMATION, original_flags: u32) {
    if let Some(dll) = dll_path() {
        let process = unsafe { (*info).hProcess };
        let _ = unsafe { rslocalehook_common::inject(process, dll) };
    }
    if original_flags & CREATE_SUSPENDED == 0 {
        let thread = unsafe { (*info).hThread };
        unsafe { ResumeThread(thread) };
    }
}

// ---------------------------------------------------------------------------
// LoadLibrary hooks (track excluded modules loaded at runtime)
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_load_library_ex_w(name: PCWSTR, file: HANDLE, flags: u32) -> HMODULE {
    let orig = unsafe { orig!(ORIG_LOAD_LIBRARY_EX_W, FnLoadLibraryExW) };
    let module = unsafe { orig(name, file, flags) };
    if !module.is_null() {
        unsafe { consider_module(module) };
    }
    module
}

unsafe extern "system" fn hook_load_library_ex_a(name: PCSTR, file: HANDLE, flags: u32) -> HMODULE {
    let orig = unsafe { orig!(ORIG_LOAD_LIBRARY_EX_A, FnLoadLibraryExA) };
    let module = unsafe { orig(name, file, flags) };
    if !module.is_null() {
        unsafe { consider_module(module) };
    }
    module
}

// ---------------------------------------------------------------------------
// IME hooks
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_imm_get_composition_string_a(
    himc: HIMC,
    index: u32,
    buf: *mut c_void,
    buf_len: u32,
) -> i32 {
    bypass!(ORIG_IMM_COMP_A, FnImmGetCompositionStringA, himc, index, buf, buf_len);
    let cp = config().codepage;
    let wsize = unsafe { ImmGetCompositionStringW(himc, index, null_mut(), 0) };
    if wsize <= 0 {
        return wsize;
    }
    let wchars = wsize as usize / 2;
    let mut wide = vec![0u16; wchars + 1];
    unsafe { ImmGetCompositionStringW(himc, index, wide.as_mut_ptr() as *mut c_void, wsize as u32) };

    let wc2mb = unsafe { orig!(ORIG_WC2MB, FnWc2Mb) };
    if buf.is_null() || buf_len == 0 {
        let needed =
            unsafe { wc2mb(cp, 0, wide.as_ptr(), wchars as i32, null_mut(), 0, null(), null_mut()) };
        return needed.max(0);
    }
    let written = unsafe {
        wc2mb(cp, 0, wide.as_ptr(), wchars as i32, buf as PSTR, buf_len as i32, null(), null_mut())
    };
    written.max(0)
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

macro_rules! attach {
    ($list:expr, $target:expr, $hook:expr, $cell:ident) => {{
        let detour = unsafe { RawDetour::new($target as *const (), $hook as *const ()) }?;
        $cell.store(detour.trampoline() as *const () as usize, Ordering::Relaxed);
        unsafe { detour.enable() }?;
        $list.push(detour);
    }};
}

fn install() -> Result<(), retour::Error> {
    let settings = config();
    let mut list: Vec<RawDetour> = Vec::new();

    // Code pages.
    attach!(list, GetACP, hook_get_acp, ORIG_GET_ACP);
    attach!(list, GetOEMCP, hook_get_oemcp, ORIG_GET_OEMCP);
    attach!(list, GetConsoleCP, hook_get_console_cp, ORIG_GET_CONSOLE_CP);
    attach!(list, GetConsoleOutputCP, hook_get_console_output_cp, ORIG_GET_CONSOLE_OUTPUT_CP);
    attach!(list, GetCPInfo, hook_get_cp_info, ORIG_GET_CP_INFO);
    attach!(list, MultiByteToWideChar, hook_mb2wc, ORIG_MB2WC);
    attach!(list, WideCharToMultiByte, hook_wc2mb, ORIG_WC2MB);

    // Locale ids.
    attach!(list, GetThreadLocale, hook_get_thread_locale, ORIG_GET_THREAD_LOCALE);
    attach!(list, GetSystemDefaultLCID, hook_get_system_default_lcid, ORIG_GET_SYS_LCID);
    attach!(list, GetUserDefaultLCID, hook_get_user_default_lcid, ORIG_GET_USER_LCID);
    attach!(list, GetSystemDefaultUILanguage, hook_get_system_default_ui_language, ORIG_GET_SYS_UILANG);
    attach!(list, GetUserDefaultUILanguage, hook_get_user_default_ui_language, ORIG_GET_USER_UILANG);
    attach!(list, GetSystemDefaultLangID, hook_get_system_default_langid, ORIG_GET_SYS_LANGID);
    attach!(list, GetUserDefaultLangID, hook_get_user_default_langid, ORIG_GET_USER_LANGID);
    attach!(list, GetLocaleInfoA, hook_get_locale_info_a, ORIG_GET_LOCALE_INFO_A);
    attach!(list, GetLocaleInfoW, hook_get_locale_info_w, ORIG_GET_LOCALE_INFO_W);

    // DBCS / traversal.
    attach!(list, IsDBCSLeadByteEx, hook_is_dbcs_lead_byte_ex, ORIG_IS_DBCS);
    attach!(list, CharNextExA, hook_char_next_ex_a, ORIG_CHAR_NEXT);
    attach!(list, CharPrevExA, hook_char_prev_ex_a, ORIG_CHAR_PREV);

    // Time zone.
    attach!(list, GetTimeZoneInformation, hook_get_time_zone_information, ORIG_GET_TZ);

    // Windows / messages.
    attach!(list, CreateWindowExA, hook_create_window_ex_a, ORIG_CREATE_WINDOW_EX_A);
    attach!(list, MessageBoxA, hook_message_box_a, ORIG_MESSAGE_BOX_A);
    attach!(list, SendMessageA, hook_send_message_a, ORIG_SEND_MESSAGE_A);
    attach!(list, DrawTextExA, hook_draw_text_ex_a, ORIG_DRAW_TEXT_EX_A);

    // Fonts.
    attach!(list, CreateFontA, hook_create_font_a, ORIG_CREATE_FONT_A);
    attach!(list, CreateFontIndirectA, hook_create_font_indirect_a, ORIG_CREATE_FONT_INDIRECT_A);

    // Clipboard.
    attach!(list, GetClipboardData, hook_get_clipboard_data, ORIG_GET_CLIPBOARD);
    attach!(list, SetClipboardData, hook_set_clipboard_data, ORIG_SET_CLIPBOARD);

    // File system.
    attach!(list, CreateDirectoryA, hook_create_directory_a, ORIG_CREATE_DIRECTORY_A);
    attach!(list, CreateFileA, hook_create_file_a, ORIG_CREATE_FILE_A);

    // Child-process propagation.
    attach!(list, CreateProcessW, hook_create_process_w, ORIG_CREATE_PROCESS_W);
    attach!(list, CreateProcessA, hook_create_process_a, ORIG_CREATE_PROCESS_A);

    // Module tracking for the caller-bypass (only matters with --no-hook).
    if !settings.no_hook.is_empty() {
        attach!(list, LoadLibraryExW, hook_load_library_ex_w, ORIG_LOAD_LIBRARY_EX_W);
        attach!(list, LoadLibraryExA, hook_load_library_ex_a, ORIG_LOAD_LIBRARY_EX_A);
    }

    // IME (optional).
    if settings.hook_ime {
        attach!(list, ImmGetCompositionStringA, hook_imm_get_composition_string_a, ORIG_IMM_COMP_A);
    }

    if let Err(existing) = DETOURS.set(Mutex::new(list)) {
        std::mem::forget(existing);
    }

    // Record any already-loaded excluded modules (e.g. statically imported GPK).
    unsafe { scan_loaded_modules() };
    Ok(())
}

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_module: *mut c_void, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        ORIGINAL_ACP.store(unsafe { GetACP() }, Ordering::Relaxed);
        let _ = config();
        let _ = dll_path();
        let _ = install();
    }
    TRUE
}

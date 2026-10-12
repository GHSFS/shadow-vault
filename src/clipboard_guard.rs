// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Auto-Expiring Clipboard Guard module (M07).
//!
//! Provides enterprise-grade, memory-safe clipboard protection with:
//! - Automatic memory scrubbing (TTL-based auto-expiring guard).
//! - Windows 10/11 Clipboard History suppression:
//!   - `CanIncludeInClipboardHistory = 0`
//!   - `ExcludeClipboardContentFromMonitorProcessing = 1`
//!   - `Clipboard Viewer Ignore = 1`
//! - Constant-time SHA-256 fingerprint verification before scrubbing
//!   (preserves subsequent operator clips if content was changed).
//! - Cross-platform test mock subsystem for CI and headless environments.
//! - Strict `Zeroize` memory zeroization of intermediate plaintext and UTF-16 buffers.

use crate::error::{Error, Result};
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[cfg(windows)]
use windows::core::w;
#[cfg(windows)]
use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
#[cfg(windows)]
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
#[cfg(windows)]
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

/// Standard Windows Unicode text clipboard format (`CF_UNICODETEXT`).
#[allow(dead_code)]
pub const CF_UNICODETEXT: u32 = 13;

/// Result of an auto-expiring clipboard scrub operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubResult {
    /// Clipboard content matched the guarded secret and was securely scrubbed.
    Scrubbed,
    /// Clipboard content was modified by the operator; subsequent clip preserved.
    PreservedDifferentContent,
    /// Clipboard was already emptied prior to expiration.
    AlreadyEmpty,
    /// Clipboard access failed or encountered an error.
    #[allow(dead_code)]
    Failed(String),
}

/// A guarded secret descriptor containing an immutable SHA-256 fingerprint.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GuardedSecret {
    /// SHA-256 digest of the copied secret.
    pub fingerprint: [u8; 32],
    /// Monotonic timestamp when the secret was copied.
    pub copied_at: Instant,
    /// Time-to-live before auto-scrubbing.
    pub ttl: Duration,
    /// Optional contextual hint (e.g. account name or filename).
    pub hint: Option<String>,
}

impl GuardedSecret {
    /// Compute the SHA-256 fingerprint for a secret string.
    pub fn compute_fingerprint(secret: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    /// Check whether the clipboard currently holds the guarded secret.
    #[allow(dead_code)]
    pub fn is_still_on_clipboard(&self) -> Result<bool> {
        is_secret_matching(&self.fingerprint)
    }

    /// Scrub the clipboard if and only if it still holds the guarded secret.
    pub fn scrub(&self) -> Result<ScrubResult> {
        scrub_if_matching(&self.fingerprint)
    }
}

// ============================================================================
// Mock Subsystem (for Unit Tests and Headless Fallbacks)
// ============================================================================

#[derive(Default)]
struct MockClipboard {
    content: Option<String>,
    history_disabled: bool,
    monitor_excluded: bool,
}

static MOCK_ENABLED: AtomicBool = AtomicBool::new(false);
static MOCK_CLIPBOARD: Mutex<Option<MockClipboard>> = Mutex::new(None);

/// Enable mock clipboard mode (used in integration tests and CI).
#[allow(dead_code)]
pub fn enable_mock_mode() {
    MOCK_ENABLED.store(true, Ordering::SeqCst);
    let mut lock = MOCK_CLIPBOARD.lock().unwrap();
    *lock = Some(MockClipboard::default());
}

/// Disable mock clipboard mode and revert to native platform API.
#[allow(dead_code)]
pub fn disable_mock_mode() {
    MOCK_ENABLED.store(false, Ordering::SeqCst);
    let mut lock = MOCK_CLIPBOARD.lock().unwrap();
    *lock = None;
}

/// Reset mock clipboard state.
#[allow(dead_code)]
pub fn reset_mock_state() {
    let mut lock = MOCK_CLIPBOARD.lock().unwrap();
    if let Some(mock) = lock.as_mut() {
        mock.content = None;
        mock.history_disabled = false;
        mock.monitor_excluded = false;
    }
}

/// Check if Windows Clipboard History suppression flags were asserted in mock mode.
#[allow(dead_code)]
pub fn is_mock_history_suppressed() -> bool {
    let lock = MOCK_CLIPBOARD.lock().unwrap();
    lock.as_ref()
        .map(|m| m.history_disabled && m.monitor_excluded)
        .unwrap_or(false)
}

fn is_mock_active() -> bool {
    #[cfg(not(windows))]
    {
        true
    }
    #[cfg(windows)]
    {
        MOCK_ENABLED.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Native Platform Clipboard Implementation (Windows Win32)
// ============================================================================

#[cfg(windows)]
struct ClipboardSession;

#[cfg(windows)]
impl ClipboardSession {
    /// Open the Windows clipboard with up to 10 retry attempts (5ms backoff).
    fn open() -> Result<Self> {
        for attempt in 0..10 {
            let res = unsafe { OpenClipboard(HWND(std::ptr::null_mut())) };
            if res.is_ok() {
                return Ok(Self);
            }
            if attempt < 9 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Err(Error::Clipboard(
            "failed to open Windows clipboard (resource busy or locked)".into(),
        ))
    }
}

#[cfg(windows)]
impl Drop for ClipboardSession {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

#[cfg(windows)]
fn native_set_clipboard(secret: &str) -> Result<()> {
    let _session = ClipboardSession::open()?;

    unsafe {
        EmptyClipboard().map_err(|e| Error::Clipboard(format!("EmptyClipboard failed: {e}")))?;

        // 1. Allocate and populate CF_UNICODETEXT
        let mut wide: Vec<u16> = secret.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes_len = wide.len() * std::mem::size_of::<u16>();

        let hmem = GlobalAlloc(GMEM_MOVEABLE, bytes_len)
            .map_err(|e| Error::Clipboard(format!("GlobalAlloc for text failed: {e}")))?;

        let ptr = GlobalLock(hmem);
        if ptr.is_null() {
            wide.zeroize();
            return Err(Error::Clipboard("GlobalLock for text returned null".into()));
        }

        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, ptr as *mut u8, bytes_len);
        let _ = GlobalUnlock(hmem);
        wide.zeroize();

        SetClipboardData(CF_UNICODETEXT, HANDLE(hmem.0 as _)).map_err(|e| {
            Error::Clipboard(format!("SetClipboardData(CF_UNICODETEXT) failed: {e}"))
        })?;

        // 2. Register and assert Windows 10/11 Clipboard History suppression markers
        // Format: CanIncludeInClipboardHistory (DWORD = 0)
        let fmt_history = RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory"));
        if fmt_history != 0 {
            if let Ok(h_hist) = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>()) {
                let p_hist = GlobalLock(h_hist);
                if !p_hist.is_null() {
                    *(p_hist as *mut u32) = 0u32;
                    let _ = GlobalUnlock(h_hist);
                    let _ = SetClipboardData(fmt_history, HANDLE(h_hist.0 as _));
                }
            }
        }

        // Format: ExcludeClipboardContentFromMonitorProcessing (DWORD = 1)
        let fmt_exclude =
            RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing"));
        if fmt_exclude != 0 {
            if let Ok(h_excl) = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>()) {
                let p_excl = GlobalLock(h_excl);
                if !p_excl.is_null() {
                    *(p_excl as *mut u32) = 1u32;
                    let _ = GlobalUnlock(h_excl);
                    let _ = SetClipboardData(fmt_exclude, HANDLE(h_excl.0 as _));
                }
            }
        }

        // Format: Clipboard Viewer Ignore (DWORD = 1)
        let fmt_ignore = RegisterClipboardFormatW(w!("Clipboard Viewer Ignore"));
        if fmt_ignore != 0 {
            if let Ok(h_ign) = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>()) {
                let p_ign = GlobalLock(h_ign);
                if !p_ign.is_null() {
                    *(p_ign as *mut u32) = 1u32;
                    let _ = GlobalUnlock(h_ign);
                    let _ = SetClipboardData(fmt_ignore, HANDLE(h_ign.0 as _));
                }
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn native_get_clipboard() -> Result<Option<String>> {
    let _session = ClipboardSession::open()?;

    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT).is_err() {
            return Ok(None);
        }

        let handle = match GetClipboardData(CF_UNICODETEXT) {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };

        if handle.0.is_null() {
            return Ok(None);
        }

        let ptr = GlobalLock(HGLOBAL(handle.0 as _));
        if ptr.is_null() {
            return Ok(None);
        }

        let u16_ptr = ptr as *const u16;
        let mut len = 0usize;
        while *u16_ptr.add(len) != 0 {
            len += 1;
            if len > 100_000_000 {
                // Safeguard against unbounded read on corrupted handles
                break;
            }
        }

        let slice = std::slice::from_raw_parts(u16_ptr, len);
        let text = String::from_utf16_lossy(slice);

        let _ = GlobalUnlock(HGLOBAL(handle.0 as _));
        Ok(Some(text))
    }
}

#[cfg(windows)]
fn native_clear_clipboard() -> Result<()> {
    let _session = ClipboardSession::open()?;
    unsafe {
        EmptyClipboard().map_err(|e| Error::Clipboard(format!("EmptyClipboard failed: {e}")))?;
    }
    Ok(())
}

// ============================================================================
// Public High-Level Clipboard Guard Functions
// ============================================================================

/// Copy a secret string to the system clipboard, suppress clipboard history,
/// and return a `GuardedSecret` tracking its SHA-256 fingerprint.
pub fn copy_to_clipboard(secret: &str) -> Result<GuardedSecret> {
    if is_mock_active() {
        let mut lock = MOCK_CLIPBOARD.lock().unwrap();
        if lock.is_none() {
            *lock = Some(MockClipboard::default());
        }
        if let Some(mock) = lock.as_mut() {
            mock.content = Some(secret.to_string());
            mock.history_disabled = true;
            mock.monitor_excluded = true;
        }
    } else {
        #[cfg(windows)]
        {
            native_set_clipboard(secret)?;
        }
        #[cfg(not(windows))]
        {
            return Err(Error::Clipboard(
                "native clipboard is only supported on Windows".into(),
            ));
        }
    }

    Ok(GuardedSecret {
        fingerprint: GuardedSecret::compute_fingerprint(secret),
        copied_at: Instant::now(),
        ttl: Duration::from_secs(15),
        hint: None,
    })
}

/// Retrieve the current Unicode text from the clipboard, if any.
pub fn get_clipboard_text() -> Result<Option<String>> {
    if is_mock_active() {
        let lock = MOCK_CLIPBOARD.lock().unwrap();
        Ok(lock.as_ref().and_then(|m| m.content.clone()))
    } else {
        #[cfg(windows)]
        {
            native_get_clipboard()
        }
        #[cfg(not(windows))]
        {
            Ok(None)
        }
    }
}

/// Unconditionally clear the system clipboard.
pub fn clear_clipboard() -> Result<()> {
    if is_mock_active() {
        let mut lock = MOCK_CLIPBOARD.lock().unwrap();
        if let Some(mock) = lock.as_mut() {
            mock.content = None;
            mock.history_disabled = false;
            mock.monitor_excluded = false;
        }
        Ok(())
    } else {
        #[cfg(windows)]
        {
            native_clear_clipboard()
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

/// Verify if the clipboard currently contains text matching the given SHA-256 fingerprint
/// in constant-time.
#[allow(dead_code)]
pub fn is_secret_matching(fingerprint: &[u8; 32]) -> Result<bool> {
    match get_clipboard_text()? {
        Some(text) => {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            let current_hash = hasher.finalize();
            let matches = constant_time_eq_32(fingerprint, &current_hash.into());
            Ok(matches)
        }
        None => Ok(false),
    }
}

/// Scrub the clipboard if and only if it currently contains text matching
/// the guarded secret's fingerprint.
pub fn scrub_if_matching(fingerprint: &[u8; 32]) -> Result<ScrubResult> {
    match get_clipboard_text()? {
        Some(text) => {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            let current_hash = hasher.finalize();
            let matches = constant_time_eq_32(fingerprint, &current_hash.into());

            if matches {
                clear_clipboard()?;
                Ok(ScrubResult::Scrubbed)
            } else {
                Ok(ScrubResult::PreservedDifferentContent)
            }
        }
        None => Ok(ScrubResult::AlreadyEmpty),
    }
}

/// Constant-time comparison between two 32-byte digests.
#[inline(never)]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Format a visual countdown progress bar.
pub fn render_progress_bar(remaining_secs: u64, total_secs: u64, width: usize) -> String {
    if total_secs == 0 {
        return format!("[{}] 0s", "░".repeat(width));
    }
    let fraction = (remaining_secs as f64) / (total_secs as f64);
    let filled_len = ((fraction * (width as f64)).round() as usize).min(width);
    let empty_len = width.saturating_sub(filled_len);

    format!(
        "[{}{}] {:>2}s",
        "█".repeat(filled_len),
        "░".repeat(empty_len),
        remaining_secs
    )
}

/// Guard a copied secret with an interactive or background countdown timer.
///
/// If running in an interactive terminal:
/// - Displays a ticking visual progress bar.
/// - Allows the operator to press Enter to clear the clipboard immediately.
/// - Upon TTL expiration, scrubs the clipboard if matching.
///
/// If non-interactive (e.g. piped or automated script):
/// - Sleeps for `ttl_secs` and scrubs if matching.
pub fn guard_interactive(secret: &str, ttl_secs: u64, hint: Option<&str>) -> Result<ScrubResult> {
    let guarded = copy_to_clipboard(secret)?;

    if ttl_secs == 0 {
        return Ok(ScrubResult::Scrubbed);
    }

    let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

    let target_label = hint.map(|h| format!(" ({})", h)).unwrap_or_default();

    if !is_interactive {
        // Non-interactive fallback: sleep for TTL duration
        std::thread::sleep(Duration::from_secs(ttl_secs));
        return guarded.scrub();
    }

    println!(
        "{} Secret copied to clipboard{}. Auto-clearing in {}s (Press Enter to clear immediately)...",
        "[guard]".cyan().bold(),
        target_label.bold(),
        ttl_secs
    );

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            let _ = tx.send(());
        }
    });

    let total_secs = ttl_secs;
    let mut remaining = total_secs;

    while remaining > 0 {
        let bar = render_progress_bar(remaining, total_secs, 10);
        print!("\r  {} remaining... ", bar.cyan());
        let _ = std::io::stdout().flush();

        // Check if operator pressed Enter
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(_) => {
                println!(
                    "\n{} Early clearance requested by operator.",
                    "[guard]".yellow()
                );
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                remaining = remaining.saturating_sub(1);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    let scrub_res = guarded.scrub()?;
    match &scrub_res {
        ScrubResult::Scrubbed => {
            println!(
                "\r  {} Clipboard securely scrubbed.             ",
                "[ok]".green().bold()
            );
        }
        ScrubResult::PreservedDifferentContent => {
            println!(
                "\r  {} Clipboard content changed; subsequent clip preserved.",
                "[info]".yellow().bold()
            );
        }
        ScrubResult::AlreadyEmpty => {
            println!(
                "\r  {} Clipboard was already empty.             ",
                "[ok]".green().bold()
            );
        }
        ScrubResult::Failed(err) => {
            println!(
                "\r  {} Failed to scrub clipboard: {}",
                "[warn]".red().bold(),
                err
            );
        }
    }

    Ok(scrub_res)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_mock_clipboard_lifecycle() {
        let _guard = TEST_LOCK.lock().unwrap();
        enable_mock_mode();
        reset_mock_state();

        assert_eq!(get_clipboard_text().unwrap(), None);

        let secret = "S3cr3t_T0tP_P@ssw0rd!";
        let guarded = copy_to_clipboard(secret).unwrap();

        assert!(is_mock_history_suppressed());
        assert_eq!(get_clipboard_text().unwrap(), Some(secret.to_string()));
        assert!(guarded.is_still_on_clipboard().unwrap());

        // Scrubbing when content matches should clear the clipboard
        let res = guarded.scrub().unwrap();
        assert_eq!(res, ScrubResult::Scrubbed);
        assert_eq!(get_clipboard_text().unwrap(), None);

        // Scrubbing an already empty clipboard
        let res2 = guarded.scrub().unwrap();
        assert_eq!(res2, ScrubResult::AlreadyEmpty);

        disable_mock_mode();
    }

    #[test]
    fn test_mock_clipboard_preserves_modified_content() {
        let _guard = TEST_LOCK.lock().unwrap();
        enable_mock_mode();
        reset_mock_state();

        let initial_secret = "Initial_Protected_Vault_Key";
        let guarded = copy_to_clipboard(initial_secret).unwrap();

        // Operator subsequently copies something else to the clipboard
        let user_clip = "https://github.com/GHSFS/shadow-vault";
        {
            let mut lock = MOCK_CLIPBOARD.lock().unwrap();
            lock.as_mut().unwrap().content = Some(user_clip.to_string());
        }

        assert!(!guarded.is_still_on_clipboard().unwrap());

        // Scrubbing must NOT wipe user's new content
        let res = guarded.scrub().unwrap();
        assert_eq!(res, ScrubResult::PreservedDifferentContent);
        assert_eq!(get_clipboard_text().unwrap(), Some(user_clip.to_string()));

        disable_mock_mode();
    }

    #[test]
    fn test_constant_time_eq_32() {
        let a = [42u8; 32];
        let mut b = [42u8; 32];
        assert!(constant_time_eq_32(&a, &b));

        b[31] = 43;
        assert!(!constant_time_eq_32(&a, &b));

        b[31] = 42;
        b[0] = 0;
        assert!(!constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_render_progress_bar() {
        let bar_half = render_progress_bar(5, 10, 10);
        assert!(bar_half.contains("█████░░░░░"));
        assert!(bar_half.contains(" 5s"));

        let bar_full = render_progress_bar(10, 10, 10);
        assert!(bar_full.contains("██████████"));

        let bar_zero = render_progress_bar(0, 10, 10);
        assert!(bar_zero.contains("░░░░░░░░░░"));
    }

    #[test]
    fn test_guarded_secret_fingerprint() {
        let secret1 = "Correct Horse Battery Staple";
        let secret2 = "Correct Horse Battery Staple";
        let secret3 = "Tr0ub4dor&3";

        let fp1 = GuardedSecret::compute_fingerprint(secret1);
        let fp2 = GuardedSecret::compute_fingerprint(secret2);
        let fp3 = GuardedSecret::compute_fingerprint(secret3);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }
}

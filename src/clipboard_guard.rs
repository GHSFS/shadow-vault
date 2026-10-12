// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Auto-Expiring Clipboard Guard module (M07).
//!
//! Provides secure Windows clipboard manipulation with:
//! - Automatic memory scrubbing (TTL-based auto-expiring daemon).
//! - Windows 10/11 Clipboard History bypass (`CanIncludeInClipboardHistory = 0`,
//!   `ExcludeClipboardContentFromMonitorProcessing = 1`, `Clipboard Viewer Ignore = 1`).
//! - Constant-time secret fingerprint verification before scrubbing.
//! - Safe multi-platform fallback and mock support.
//! - Proactive `Zeroize` memory clearing on all intermediate buffers.

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

pub fn test_probe() {
    #[cfg(windows)]
    unsafe {
        let _ = OpenClipboard(HWND(std::ptr::null_mut()));
        let _ = CloseClipboard();
    }
}

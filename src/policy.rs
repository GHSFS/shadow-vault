// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Time-Lock & Expiration Policy Header engine (`src/policy.rs`).
//!
//! Provides cryptographically authenticated time-bound policies for `.svault` containers:
//! - `not_before`: UTC Unix timestamp before which decryption is refused (time-lock).
//! - `expires_at`: UTC Unix timestamp after which decryption is refused (expiration).
//! - AEAD Authentication: The serialized policy header is authenticated as Additional
//!   Authenticated Data (AAD) in ChaCha20-Poly1305, preventing timestamp tampering.
//! - Self-contained CRC-32 integrity and wire header verification.
//! - Human-readable ISO-8601 formatting and relative duration parser (`+1h`, `24h`, `7d`).

use crate::error::{Error, Result};
use crc32fast::Hasher as Crc32Hasher;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const POLICY_MAGIC: &[u8; 4] = b"SVPO";
pub const POLICY_VERSION: u8 = 1;
pub const MAX_DESCRIPTION_LEN: usize = 512;
pub const BASE_WIRE_LEN: usize = 4 + 1 + 4 + 8 + 8 + 8 + 2 + 4; // 39 bytes

/// Current execution status of a time policy evaluated against a given timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PolicyStatus {
    /// Policy is currently active and permitted for decryption.
    Active {
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_in_secs: Option<u64>,
    },
    /// Vault is time-locked and cannot be decrypted until `not_before`.
    TimeLocked {
        not_before: u64,
        remaining_secs: u64,
    },
    /// Vault has expired and decryption is strictly forbidden.
    Expired {
        expires_at: u64,
        expired_secs_ago: u64,
    },
}

/// Cryptographically authenticated container policy header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHeader {
    /// Optional UTC Unix timestamp (seconds) before which decryption is forbidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,

    /// Optional UTC Unix timestamp (seconds) after which decryption is forbidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// UTC Unix timestamp (seconds) when this policy was created.
    pub created_at: u64,

    /// Policy configuration and enforcement flags.
    pub flags: u32,

    /// Optional description or administrative policy identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl PolicyHeader {
    /// Create a new policy header with validation.
    pub fn new(
        not_before: Option<u64>,
        expires_at: Option<u64>,
        description: Option<String>,
    ) -> Result<Self> {
        let created_at = current_utc_timestamp();
        Self::with_details(not_before, expires_at, created_at, 0, description)
    }

    /// Construct a policy header with explicit creation time and flags.
    pub fn with_details(
        not_before: Option<u64>,
        expires_at: Option<u64>,
        created_at: u64,
        flags: u32,
        description: Option<String>,
    ) -> Result<Self> {
        if let (Some(nb), Some(exp)) = (not_before, expires_at) {
            if nb > exp {
                return Err(Error::Policy(format!(
                    "not_before timestamp ({nb}) cannot be later than expires_at ({exp})"
                )));
            }
        }

        if let Some(ref desc) = description {
            if desc.len() > MAX_DESCRIPTION_LEN {
                return Err(Error::Policy(format!(
                    "policy description exceeds maximum length of {MAX_DESCRIPTION_LEN} bytes (got {})",
                    desc.len()
                )));
            }
        }

        Ok(Self {
            not_before,
            expires_at,
            created_at,
            flags,
            description,
        })
    }

    /// Check if the vault policy is currently active at the given timestamp.
    #[allow(dead_code)]
    pub fn is_active_at(&self, now: u64) -> bool {
        matches!(self.status_at(now), PolicyStatus::Active { .. })
    }

    /// Evaluate the policy status at a specific Unix timestamp.
    pub fn status_at(&self, now: u64) -> PolicyStatus {
        if let Some(nb) = self.not_before {
            if now < nb {
                return PolicyStatus::TimeLocked {
                    not_before: nb,
                    remaining_secs: nb.saturating_sub(now),
                };
            }
        }

        if let Some(exp) = self.expires_at {
            if now > exp {
                return PolicyStatus::Expired {
                    expires_at: exp,
                    expired_secs_ago: now.saturating_sub(exp),
                };
            }
        }

        let expires_in_secs = self.expires_at.map(|exp| exp.saturating_sub(now));
        PolicyStatus::Active { expires_in_secs }
    }

    /// Validate that the container can be decrypted at the given timestamp.
    pub fn validate_at(&self, now: u64) -> Result<()> {
        match self.status_at(now) {
            PolicyStatus::Active { .. } => Ok(()),
            PolicyStatus::TimeLocked {
                not_before,
                remaining_secs,
            } => Err(Error::Policy(format!(
                "vault is time-locked until {} (unlocks in {}s) — decryption refused",
                format_iso8601_utc(not_before),
                remaining_secs
            ))),
            PolicyStatus::Expired {
                expires_at,
                expired_secs_ago,
            } => Err(Error::Policy(format!(
                "vault expired at {} (expired {}s ago) — decryption refused",
                format_iso8601_utc(expires_at),
                expired_secs_ago
            ))),
        }
    }

    /// Serialize the policy header to canonical binary format for storage and AEAD authentication.
    pub fn to_bytes(&self) -> Vec<u8> {
        let desc_bytes = self.description.as_deref().unwrap_or("").as_bytes();
        let desc_len = desc_bytes.len().min(MAX_DESCRIPTION_LEN) as u16;
        let mut out = Vec::with_capacity(BASE_WIRE_LEN + desc_bytes.len());

        out.extend_from_slice(POLICY_MAGIC);
        out.push(POLICY_VERSION);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&self.not_before.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&self.expires_at.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&desc_len.to_le_bytes());
        out.extend_from_slice(&desc_bytes[..desc_len as usize]);

        let mut hasher = Crc32Hasher::new();
        hasher.update(&out);
        let crc = hasher.finalize();
        out.extend_from_slice(&crc.to_le_bytes());

        out
    }

    /// Deserialize and verify a policy header from raw binary bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < BASE_WIRE_LEN {
            return Err(Error::Policy(format!(
                "policy header truncated ({} bytes, minimum {})",
                data.len(),
                BASE_WIRE_LEN
            )));
        }

        if &data[0..4] != POLICY_MAGIC {
            return Err(Error::Policy(
                "invalid policy header magic (expected SVPO)".into(),
            ));
        }

        let version = data[4];
        if version != POLICY_VERSION {
            return Err(Error::Policy(format!(
                "unsupported policy version {version} (expected {POLICY_VERSION})"
            )));
        }

        let flags = u32::from_le_bytes(data[5..9].try_into().unwrap());
        let created_at = u64::from_le_bytes(data[9..17].try_into().unwrap());
        let raw_nb = u64::from_le_bytes(data[17..25].try_into().unwrap());
        let raw_exp = u64::from_le_bytes(data[25..33].try_into().unwrap());
        let desc_len = u16::from_le_bytes(data[33..35].try_into().unwrap()) as usize;

        let expected_total_len = BASE_WIRE_LEN + desc_len;
        if data.len() < expected_total_len {
            return Err(Error::Policy(format!(
                "policy header payload truncated (expected {expected_total_len} bytes, got {})",
                data.len()
            )));
        }

        let desc_start = 35;
        let desc_end = desc_start + desc_len;
        let stored_crc = u32::from_le_bytes(data[desc_end..desc_end + 4].try_into().unwrap());

        let mut hasher = Crc32Hasher::new();
        hasher.update(&data[..desc_end]);
        let computed_crc = hasher.finalize();

        if stored_crc != computed_crc {
            return Err(Error::Policy(format!(
                "policy CRC-32 checksum mismatch (stored: {stored_crc:#010x}, computed: {computed_crc:#010x})"
            )));
        }

        let description = if desc_len > 0 {
            let s = std::str::from_utf8(&data[desc_start..desc_end])
                .map_err(|e| Error::Policy(format!("invalid UTF-8 in policy description: {e}")))?;
            Some(s.to_string())
        } else {
            None
        };

        let not_before = if raw_nb > 0 { Some(raw_nb) } else { None };
        let expires_at = if raw_exp > 0 { Some(raw_exp) } else { None };

        Self::with_details(not_before, expires_at, created_at, flags, description)
    }

    /// One-line human-readable summary of policy status.
    pub fn status_summary(&self, now: u64) -> String {
        match self.status_at(now) {
            PolicyStatus::Active { expires_in_secs } => {
                if let Some(rem) = expires_in_secs {
                    format!("ACTIVE (expires in {rem}s / {})", format_duration(rem))
                } else {
                    "ACTIVE (no expiration)".to_string()
                }
            }
            PolicyStatus::TimeLocked { remaining_secs, .. } => {
                format!(
                    "TIME-LOCKED (unlocks in {remaining_secs}s / {})",
                    format_duration(remaining_secs)
                )
            }
            PolicyStatus::Expired {
                expired_secs_ago, ..
            } => {
                format!(
                    "EXPIRED (expired {expired_secs_ago}s ago / {} ago)",
                    format_duration(expired_secs_ago)
                )
            }
        }
    }

    /// Formatted ISO-8601 string for `not_before`.
    pub fn format_not_before(&self) -> Option<String> {
        self.not_before.map(format_iso8601_utc)
    }

    /// Formatted ISO-8601 string for `expires_at`.
    pub fn format_expires_at(&self) -> Option<String> {
        self.expires_at.map(format_iso8601_utc)
    }

    /// Formatted ISO-8601 string for `created_at`.
    pub fn format_created_at(&self) -> String {
        format_iso8601_utc(self.created_at)
    }
}

/// Returns the current system UTC timestamp in seconds.
pub fn current_utc_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Convert seconds count into human-readable duration string (e.g. `2d 4h 12m 30s`).
pub fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "0s".to_string();
    }
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{secs}s"));
    }
    parts.join(" ")
}

/// Convert Unix timestamp to ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_iso8601_utc(timestamp: u64) -> String {
    let secs_of_day = timestamp % 86400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let days = (timestamp / 86400) as i64;
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse a duration string like `30s`, `15m`, `2h`, `7d`, `4w` into seconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    let trimmed = s.trim().trim_start_matches('+');
    if trimmed.is_empty() {
        return Err(Error::Policy("duration string is empty".into()));
    }

    let split_pos = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());

    let (val_str, unit_str) = trimmed.split_at(split_pos);
    let val: u64 = val_str
        .parse()
        .map_err(|_| Error::Policy(format!("invalid duration number in '{s}'")))?;

    let unit = unit_str.trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "s" | "sec" | "seconds" => 1,
        "m" | "min" | "minutes" => 60,
        "h" | "hr" | "hours" => 3600,
        "d" | "day" | "days" => 86400,
        "w" | "week" | "weeks" => 86400 * 7,
        "y" | "year" | "years" => 86400 * 365,
        other => {
            return Err(Error::Policy(format!(
                "unknown duration unit '{other}' in '{s}' (supported: s, m, h, d, w, y)"
            )));
        }
    };

    val.checked_mul(multiplier)
        .ok_or_else(|| Error::Policy(format!("duration overflow in '{s}'")))
}

/// Parse either an ISO-8601 timestamp, a relative offset (`+1h`, `+7d`), or a raw Unix timestamp.
pub fn parse_timestamp_or_duration(s: &str, reference_now: u64) -> Result<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::Policy("timestamp input is empty".into()));
    }

    if trimmed.starts_with('+') {
        let dur = parse_duration(trimmed)?;
        return reference_now
            .checked_add(dur)
            .ok_or_else(|| Error::Policy(format!("timestamp overflow adding '{trimmed}' to now")));
    }

    if let Ok(raw_ts) = trimmed.parse::<u64>() {
        return Ok(raw_ts);
    }

    // Try parsing as ISO-8601 date-time: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS[Z]
    parse_iso8601_utc(trimmed)
}

/// Parse an ISO-8601 UTC date or datetime string into Unix timestamp.
pub fn parse_iso8601_utc(s: &str) -> Result<u64> {
    let cleaned = s.trim().trim_end_matches('Z').trim_end_matches('z');
    let parts: Vec<&str> = cleaned.split(['T', ' ']).collect();

    let date_str = parts[0];
    let date_parts: Vec<&str> = date_str.split('-').collect();
    if date_parts.len() != 3 {
        return Err(Error::Policy(format!(
            "invalid ISO-8601 date format '{s}' (expected YYYY-MM-DD)"
        )));
    }

    let year: i32 = date_parts[0]
        .parse()
        .map_err(|_| Error::Policy(format!("invalid year in '{s}'")))?;
    let month: u32 = date_parts[1]
        .parse()
        .map_err(|_| Error::Policy(format!("invalid month in '{s}'")))?;
    let day: u32 = date_parts[2]
        .parse()
        .map_err(|_| Error::Policy(format!("invalid day in '{s}'")))?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(Error::Policy(format!("out-of-range date values in '{s}'")));
    }

    let (hour, minute, second) = if parts.len() > 1 {
        let time_str = parts[1];
        let time_parts: Vec<&str> = time_str.split(':').collect();
        if time_parts.len() < 2 || time_parts.len() > 3 {
            return Err(Error::Policy(format!(
                "invalid ISO-8601 time format in '{s}' (expected HH:MM or HH:MM:SS)"
            )));
        }
        let h: u64 = time_parts[0]
            .parse()
            .map_err(|_| Error::Policy(format!("invalid hour in '{s}'")))?;
        let m: u64 = time_parts[1]
            .parse()
            .map_err(|_| Error::Policy(format!("invalid minute in '{s}'")))?;
        let sec: u64 = if time_parts.len() == 3 {
            time_parts[2]
                .parse()
                .map_err(|_| Error::Policy(format!("invalid second in '{s}'")))?
        } else {
            0
        };

        if h > 23 || m > 59 || sec > 59 {
            return Err(Error::Policy(format!("out-of-range time values in '{s}'")));
        }
        (h, m, sec)
    } else {
        (0, 0, 0)
    };

    let days = ymd_to_days(year, month, day);
    if days < 0 {
        return Err(Error::Policy(format!(
            "date '{s}' is before Unix epoch (1970)"
        )));
    }

    let total_secs = (days as u64)
        .checked_mul(86400)
        .and_then(|s| s.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or_else(|| Error::Policy(format!("timestamp overflow parsing '{s}'")))?;

    Ok(total_secs)
}

/// Howard Hinnant's civil day to (year, month, day) algorithm.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Howard Hinnant's (year, month, day) to civil day algorithm.
fn ymd_to_days(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe as i64 - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_conversion_roundtrip() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
        assert_eq!(ymd_to_days(1970, 1, 1), 0);

        let test_cases = [
            (1970, 1, 1),
            (2000, 2, 29), // leap year
            (2024, 2, 29), // leap year
            (2026, 10, 13),
            (2038, 1, 19),
            (2099, 12, 31),
        ];

        for (y, m, d) in test_cases {
            let days = ymd_to_days(y, m, d);
            let roundtrip = days_to_ymd(days);
            assert_eq!((y, m, d), roundtrip, "failed for {y}-{m}-{d}");
        }
    }

    #[test]
    fn test_iso8601_formatting_and_parsing() {
        let ts = 1791850000; // specific future timestamp
        let formatted = format_iso8601_utc(ts);
        let parsed = parse_iso8601_utc(&formatted).unwrap();
        assert_eq!(ts, parsed);

        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_iso8601_utc("1970-01-01 00:00:00").unwrap(), 0);
        assert_eq!(parse_iso8601_utc("1970-01-01").unwrap(), 0);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_duration("+1w").unwrap(), 7 * 86400);
        assert!(parse_duration("invalid").is_err());
    }

    #[test]
    fn test_parse_timestamp_or_duration() {
        let now = 1000000;
        assert_eq!(
            parse_timestamp_or_duration("+1h", now).unwrap(),
            1000000 + 3600
        );
        assert_eq!(
            parse_timestamp_or_duration("1791850000", now).unwrap(),
            1791850000
        );
    }

    #[test]
    fn test_policy_header_serialization_roundtrip() {
        let header = PolicyHeader::with_details(
            Some(1700000000),
            Some(1800000000),
            1690000000,
            1,
            Some("Q4 Escrow Release".to_string()),
        )
        .unwrap();

        let bytes = header.to_bytes();
        let decoded = PolicyHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_policy_header_corrupted_crc_fails() {
        let header = PolicyHeader::with_details(
            Some(1700000000),
            Some(1800000000),
            1690000000,
            0,
            Some("Escrow".to_string()),
        )
        .unwrap();

        let mut bytes = header.to_bytes();
        let len = bytes.len();
        bytes[len - 1] ^= 0xFF; // corrupt CRC byte
        assert!(PolicyHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_policy_status_evaluations() {
        let header = PolicyHeader::with_details(Some(1000), Some(2000), 500, 0, None).unwrap();

        // Before not_before -> TimeLocked
        assert!(matches!(
            header.status_at(999),
            PolicyStatus::TimeLocked {
                not_before: 1000,
                remaining_secs: 1
            }
        ));
        assert!(header.validate_at(999).is_err());

        // At not_before -> Active
        assert!(matches!(
            header.status_at(1000),
            PolicyStatus::Active {
                expires_in_secs: Some(1000)
            }
        ));
        assert!(header.validate_at(1000).is_ok());

        // Mid-range -> Active
        assert!(matches!(
            header.status_at(1500),
            PolicyStatus::Active {
                expires_in_secs: Some(500)
            }
        ));
        assert!(header.validate_at(1500).is_ok());

        // At expires_at -> Active (exact boundary is still valid)
        assert!(matches!(
            header.status_at(2000),
            PolicyStatus::Active {
                expires_in_secs: Some(0)
            }
        ));
        assert!(header.validate_at(2000).is_ok());

        // After expires_at -> Expired
        assert!(matches!(
            header.status_at(2001),
            PolicyStatus::Expired {
                expires_at: 2000,
                expired_secs_ago: 1
            }
        ));
        assert!(header.validate_at(2001).is_err());
    }
}

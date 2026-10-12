// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cryptographic failure: {0}")]
    Crypto(String),

    #[error("invalid container or carrier format: {0}")]
    Format(String),

    #[error("Windows DPAPI error: {0}")]
    Dpapi(String),

    #[error("clipboard error: {0}")]
    Clipboard(String),

    #[error("archive error: {0}")]
    Archive(String),
}

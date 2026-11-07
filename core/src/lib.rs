//! Honor Tool core library.
//!
//! Split into independent modules so the parsing/patching logic (which is the
//! risky part) is pure, deterministic, and unit-tested against real firmware
//! dumps, while all device interaction lives behind a thin adb abstraction.
//!
//! # Safety model
//! - Nothing here ever writes to a device unless an explicit `write` path is
//!   requested, and every write path takes a verified backup first.
//! - LK patching refuses any firmware whose patch-site bytes do not exactly
//!   match a known original. Unknown builds are rejected, never guessed at.

pub mod model;
pub mod lk;
pub mod seccfg;
pub mod adb;
pub mod device;
pub mod partition;
pub mod unlock;
pub mod proto;

pub use model::*;

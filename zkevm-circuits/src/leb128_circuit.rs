//! The leb128 circuit implementation.

/// leb128 circuit
pub mod circuit;
/// LEB128 circuit tester
#[cfg(any(feature = "test", test))]
pub mod dev;

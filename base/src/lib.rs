// =============================================================================
// ATTRIBUTES
// =============================================================================

#![allow(dead_code, clippy::large_enum_variant)]
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

// =============================================================================
// MODULES
// =============================================================================

// -----------------------------------------------------------------------------
// PUBLIC MODULES
//   These should always be marked `pub`, they will always be exposed.
//   We expect that the client must path into the modules to access the types.
// -----------------------------------------------------------------------------

pub mod commands;
pub mod constants;
pub mod types;

// -----------------------------------------------------------------------------
// TESTS
//   TODO: Move these closer to the tested code instead of having one test mod.
//   We should do less of these huge test files with all the tests in one file.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests;

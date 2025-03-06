//! Please see "simulator_tests.rs" for details.
//!
//! Add at least one test module file for each chapter in TPM command spec.
//! If there are many tests for a single command, it is recommended to split into command submodules:
//!
//! <chaptername>/mod.rs
//! <chaptername>/<commandname_1>.rs
//! <chaptername>/<commandname_2>.rs
pub mod capability;
pub mod nv_storage;
pub mod random;

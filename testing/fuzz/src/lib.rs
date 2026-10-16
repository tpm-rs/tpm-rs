//! Differential fuzzing of `tpm-rs` against the C reference TPMs: the
//! multi-round conversation model and driver used by the `diff_conversation`
//! fuzz target.
//!
//! One fuzz input is a [`model::Conversation`]: a sequence of TPM commands
//! sent to one fresh, started [`testing::Tpm`], which mirrors every command to
//! the C references and compares each response. Later commands may reuse
//! values from earlier responses, collected in the [`pool::ValuePool`].
//!
//! * [`model`]: the input model and its byte encoding (decoder and encoder);
//! * [`wire`]: parsing and well-formedness checks of command and response
//!   buffers;
//! * [`pool`]: the value pool (response handles, typed response fields and
//!   driver-tracked facts such as NV indices, auth values and flushed
//!   handles);
//! * [`builder`]: operand resolution, fix-ups and the command builder;
//! * [`session`]: the session engine (password, HMAC and policy sessions);
//! * [`driver`]: one round (build, send, check, extract, update) and the
//!   finding signatures.

#![forbid(unsafe_code)]

pub mod builder;
pub mod driver;
pub mod model;
pub mod pool;
pub mod session;
pub mod wire;

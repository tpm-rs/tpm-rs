// =============================================================================
// USES
// =============================================================================

use crate::{constants::*, types::*};
use core::mem::size_of;
use tpm2_rs_errors::TpmRcResult;
use tpm2_rs_marshal::Marshalable;
use tpm2_rs_unionify::UnionSize;

// =============================================================================
// MACROS
// =============================================================================

macro_rules! impl_try_marshalable_tpm2b_simple {
    ($T:ty, $F:ident) => {
        impl crate::types::Tpm2bSimple for $T {
            const MAX_BUFFER_SIZE: usize = core::mem::size_of::<$T>() - core::mem::size_of::<u16>();

            fn get_size(&self) -> u16 {
                self.size
            }

            fn get_buffer(&self) -> &[u8] {
                &self.$F[0..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> tpm2_rs_errors::TpmRcResult<Self> {
                // Overflow check
                if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
                    return Err(tpm2_rs_errors::TpmRcError::Size);
                }

                let mut dest: Self = Self {
                    size: buffer.len() as u16,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };
                dest.$F[..buffer.len()].copy_from_slice(buffer);
                Ok(dest)
            }
        }

        impl Default for $T {
            fn default() -> Self {
                Self {
                    size: 0,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                }
            }
        }

        impl Marshalable for $T {
            fn try_unmarshal(
                buffer: &mut tpm2_rs_marshal::UnmarshalBuf,
            ) -> tpm2_rs_errors::TpmRcResult<Self> {
                let got_size = u16::try_unmarshal(buffer)?;
                // Ensure the buffer is large enough to fullfill the size indicated
                let sized_buffer = buffer.get(got_size as usize);
                if !sized_buffer.is_some() {
                    return Err(tpm2_rs_errors::TpmRcError::Memory);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if sized_buffer.unwrap().len() > dest.$F.len() {
                    return Err(tpm2_rs_errors::TpmRcError::Memory);
                }
                dest.$F[..got_size.into()].copy_from_slice(&sized_buffer.unwrap());

                Ok(dest)
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_errors::TpmRcResult<usize> {
                let used = self.size.try_marshal(buffer)?;
                let (_, rest) = buffer.split_at_mut(used);
                let buffer_marsh = self.get_size() as usize;
                if buffer_marsh > (core::cmp::max(Self::MAX_BUFFER_SIZE, rest.len())) {
                    return Err(tpm2_rs_errors::TpmRcError::Memory);
                }
                rest[..buffer_marsh].copy_from_slice(&self.$F[..buffer_marsh]);
                Ok(used + buffer_marsh)
            }
        }
    };
}

macro_rules! impl_try_marshalable_tpm2b_struct {
    ($T:ty, $StructType:ty, $F:ident) => {
        impl Tpm2bStruct for $T {
            type StructType = $StructType;

            fn from_struct(val: &Self::StructType) -> tpm2_rs_errors::TpmRcResult<Self> {
                let mut x = Self::default();
                x.size = val.try_marshal(&mut x.$F)? as u16;
                Ok(x)
            }

            fn to_struct(&self) -> tpm2_rs_errors::TpmRcResult<Self::StructType> {
                let mut buf =
                    tpm2_rs_marshal::UnmarshalBuf::new(&self.$F[0..self.get_size() as usize]);
                Self::StructType::try_unmarshal(&mut buf)
            }
        }
    };
}

// =============================================================================
// MODULES
// =============================================================================

mod private;
pub use private::*;

// =============================================================================
// HELPER TRAITS
// =============================================================================

pub trait Tpm2bSimple {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> TpmRcResult<Self>
    where
        Self: Sized;
}

/// Provides conversion to/from a struct type for TPM2B types that don't hold a bytes buffer.
pub trait Tpm2bStruct: Tpm2bSimple {
    type StructType: Marshalable;

    /// Marshals the value into the 2b holder.
    fn from_struct(val: &Self::StructType) -> TpmRcResult<Self>
    where
        Self: Sized;

    /// Extracts the struct value from the 2b holder.
    fn to_struct(&self) -> TpmRcResult<Self::StructType>;
}

// =============================================================================
// USES
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bAttest {
    size: u16,
    pub attestation_data: [u8; size_of::<TpmsAttest>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bAttest, attestation_data}

pub type Tpm2bAuth = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextData {
    size: u16,
    pub buffer: [u8; size_of::<TpmsContextData>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bContextData, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextSensitive {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CONTEXT_SIZE as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bContextSensitive, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bCreationData {
    size: u16,
    pub creation_data: [u8; size_of::<TpmsCreationData>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bCreationData, creation_data}
impl_try_marshalable_tpm2b_struct! {Tpm2bCreationData, TpmsCreationData, creation_data}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: u16,
    pub buffer: [u8; TpmtHa::UNION_SIZE],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bData, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDerive {
    size: u16,
    pub buffer: [u8; size_of::<TpmsDerive>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDigest {
    size: u16,
    pub buffer: [u8; TpmtHa::UNION_SIZE],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bDigest, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    pub buffer: [u8; TPM2_MAX_ECC_KEY_BYTES as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bEccParameter, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccPoint {
    size: u16,
    pub point: [u8; size_of::<TpmsEccPoint>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    pub secret: [u8; TpmuEncryptedSecret::UNION_SIZE],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bEncryptedSecret, secret}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEvent {
    size: u16,
    pub buffer: [u8; 1024],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bEvent, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIdObject {
    size: u16,
    pub credential: [u8; size_of::<TpmsIdObject>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bIdObject, credential}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIv {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_BLOCK_SIZE as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bIv, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    pub buffer: [u8; TPM2_LABEL_MAX_BUFFER as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bLabel, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_DIGEST_BUFFER as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bMaxBuffer, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_NV_BUFFER_SIZE as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bMaxNvBuffer, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bName {
    size: u16,
    pub name: [u8; TpmuName::UNION_SIZE],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bName, name}

pub type Tpm2bNonce = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bNvPublic {
    size: u16,
    pub nv_public: [u8; size_of::<TpmsNvPublic>()],
}

pub type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    size: u16,
    pub buffer: [u8; (TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivateKeyRsa, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateVendorSpecific {
    size: u16,
    pub buffer: [u8; TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivateVendorSpecific, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublic {
    size: u16,
    pub public_area: [u8; size_of::<TpmtPublic>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bPublic, public_area}
impl_try_marshalable_tpm2b_struct! {Tpm2bPublic, TpmtPublic, public_area}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    pub buffer: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bPublicKeyRsa, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveCreate {
    size: u16,
    pub sensitive: [u8; size_of::<TpmsSensitiveCreate>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bSensitiveCreate, sensitive}
impl_try_marshalable_tpm2b_struct! {Tpm2bSensitiveCreate, TpmsSensitiveCreate, sensitive}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveData {
    size: u16,
    pub buffer: [u8; TpmuSensitiveCreate::UNION_SIZE],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bSensitiveData, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitive {
    size: u16,
    pub sensitive_area: [u8; size_of::<TpmtSensitive>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSymKey {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_KEY_BYTES as usize],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bSymKey, buffer}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bTemplate {
    size: u16,
    pub buffer: [u8; size_of::<TpmtPublic>()],
}
impl_try_marshalable_tpm2b_simple! {Tpm2bTemplate, buffer}

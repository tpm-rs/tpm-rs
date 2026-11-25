//! Handle and Name types for TPM 2.0 command handle areas and `cpHash` calculation.
use crate::{Marshal, TpmHt, TpmtHa, Unmarshal, errors::UnmarshalError};

/// `TPM_HANDLE`, `TPM_RH`, and `TPM_HC` defined in TPM 2.0 Part 2: Structures, Section 7 (Tables 28–30) and Section 9 (Tables 40–50).
///
/// Represents 32-bit numeric handles used to reference TPM resources (transient/persistent objects,
/// NV indices, PCRs, authorization sessions, and permanent reserved handles such as `RH_OWNER`, `RH_PLATFORM`, `RH_NULL`).
/// The top 8 bits determine the handle type ([`TpmHt`]).
#[doc(alias = "TPM_HANDLE")]
#[doc(alias = "TPM_RH")]
#[doc(alias = "TPM_HC")]
#[doc(alias = "TPMI_DH_OBJECT")]
#[doc(alias = "TPMI_DH_PARENT")]
#[doc(alias = "TPMI_DH_PERSISTENT")]
#[doc(alias = "TPMI_DH_ENTITY")]
#[doc(alias = "TPMI_DH_PCR")]
#[doc(alias = "TPMI_SH_AUTH_SESSION")]
#[doc(alias = "TPMI_DH_CONTEXT")]
#[doc(alias = "TPMI_RH_HIERARCHY")]
#[doc(alias = "TPMI_RH_NV_INDEX")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Handle(pub u32);

impl Handle {
    pub fn handle_type(self) -> Option<TpmHt> {
        self.0.to_be_bytes()[0].try_into().ok()
    }

    pub const RH_OWNER: Handle = Handle(0x40000001);
    pub const RH_NULL: Handle = Handle(0x40000007);
    pub const RS_PW: Handle = Handle(0x40000009);
    pub const RH_LOCKOUT: Handle = Handle(0x4000000A);
    pub const RH_ENDORSEMENT: Handle = Handle(0x4000000B);
    pub const RH_PLATFORM: Handle = Handle(0x4000000C);
    pub const RH_PLATFORM_NV: Handle = Handle(0x4000000D);
    pub const RH_ACT_0: Handle = Handle(0x40000110);
    pub const RH_ACT_1: Handle = Handle(0x40000111);
    pub const RH_ACT_2: Handle = Handle(0x40000112);
    pub const RH_ACT_3: Handle = Handle(0x40000113);
    pub const RH_ACT_4: Handle = Handle(0x40000114);
    pub const RH_ACT_5: Handle = Handle(0x40000115);
    pub const RH_ACT_6: Handle = Handle(0x40000116);
    pub const RH_ACT_7: Handle = Handle(0x40000117);
    pub const RH_ACT_8: Handle = Handle(0x40000118);
    pub const RH_ACT_9: Handle = Handle(0x40000119);
    pub const RH_ACT_A: Handle = Handle(0x4000011A);
    pub const RH_ACT_B: Handle = Handle(0x4000011B);
    pub const RH_ACT_C: Handle = Handle(0x4000011C);
    pub const RH_ACT_D: Handle = Handle(0x4000011D);
    pub const RH_ACT_E: Handle = Handle(0x4000011E);
    pub const RH_ACT_F: Handle = Handle(0x4000011F);
    pub const RH_FW_OWNER: Handle = Handle(0x40000140);
    pub const RH_FW_ENDORSEMENT: Handle = Handle(0x40000141);
    pub const RH_FW_PLATFORM: Handle = Handle(0x40000142);
    pub const RH_FW_NULL: Handle = Handle(0x40000143);
    pub const RH_SVN_OWNER_BASE: Handle = Handle(0x40010000);
    pub const RH_SVN_ENDORSEMENT_BASE: Handle = Handle(0x40020000);
    pub const RH_SVN_PLATFORM_BASE: Handle = Handle(0x40030000);
    pub const RH_SVN_NULL_BASE: Handle = Handle(0x40040000);
}

impl Marshal for Handle {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Handle {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
}

/// The Name of a TPM entity, defined in TPM 2.0 Part 1, Section 13.
///
/// [`Marshal`] / [`Unmarshal`] use the `TPM2B_NAME` wire format (a `u16` size
/// followed by the Name). Use [`Name::bytes`] for the Name without the size,
/// which is what `cpHash` and policy digests hash.
#[doc(alias = "TPM2B_NAME")]
#[doc(alias = "TPMU_NAME")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Name<'a> {
    /// No Name: a sequence object, or an object whose `nameAlg` is
    /// `TPM_ALG_NULL`.
    Empty,
    /// The handle itself: PCRs, sessions, and permanent handles.
    Handle(Handle),
    /// `nameAlg || H(public area)`: objects and NV indices.
    Digest(TpmtHa<'a>),
}

// So a handle always fits in the buffer for `Name::bytes`.
const _: () = assert!(Handle::MAX_SIZE <= TpmtHa::MAX_SIZE);

impl Name<'_> {
    /// Writes the Name into `buf` and returns it, without the `TPM2B_NAME`
    /// size.
    pub fn bytes<'b>(&self, buf: &'b mut [u8; TpmtHa::MAX_SIZE]) -> &'b [u8] {
        let len = match self {
            Self::Empty => 0,
            Self::Handle(h) => h.marshal(buf.first_chunk_mut().unwrap()),
            Self::Digest(d) => d.marshal(buf),
        };
        &buf[..len]
    }
}

impl Marshal for Name<'_> {
    const MAX_SIZE: usize = u16::MAX_SIZE + TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; Name::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let (size, rest) = dst.split_first_chunk_mut().unwrap();
        let len = self.bytes(rest.try_into().unwrap()).len();
        (len as u16).marshal(size) + len
    }
}

impl<'a> Unmarshal<'a> for Name<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let len: usize = u16::unmarshal(src)?.into();
        let mut buf: &'a [u8];
        (buf, *src) = src.split_at_checked(len).ok_or(UnmarshalError)?;
        // A digest Name is always longer than a handle.
        let name = match len {
            0 => Self::Empty,
            Handle::MAX_SIZE => Self::Handle(Handle::unmarshal(&mut buf)?),
            _ => Self::Digest(TpmtHa::unmarshal(&mut buf)?),
        };
        match buf.len() {
            0 => Ok(name),
            _ => Err(UnmarshalError),
        }
    }
}

/// A sequence object handle (from `TPM2_HashSequenceStart` and similar
/// commands). Its Name is always [`Name::Empty`].
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SequenceHandle(pub Handle);

/// An NV index handle and its Name.
///
/// The Name changes when the index is written or locked, so it may need to be
/// recomputed or read again with `TPM2_NV_ReadPublic`.
#[derive(Copy, Clone)]
pub struct NvHandle<'a> {
    pub index: Handle,
    pub digest: TpmtHa<'a>,
}

impl NvHandle<'_> {
    pub const NV_INDEX_FIRST: Handle = Handle(0x01000000);
    pub const NV_INDEX_LAST: Handle = Handle(0x01FFFFFF);
}

/// A transient or persistent object handle and its Name.
///
/// `digest` is `None` when the object's Name is empty, as for an object loaded
/// with `TPM2_LoadExternal` whose `nameAlg` is `TPM_ALG_NULL`.
#[derive(Copy, Clone)]
pub struct ObjectHandle<'a> {
    pub handle: Handle,
    pub digest: Option<TpmtHa<'a>>,
}

/// A handle together with the form of its Name.
///
/// Every command handle converts into this type for [`Command::handles`](crate::Command::handles).
/// It is also the field type for handles that accept several kinds of entity:
/// `TPMI_RH_NV_AUTH`, `TPMI_DH_ENTITY`, and object handles that may be
/// `TPM_RH_NULL`.
#[derive(Copy, Clone)]
pub enum EntityHandle<'a> {
    /// The Name is [`Name::Empty`].
    Empty(Handle),
    /// The Name is [`Name::Handle`].
    Handle(Handle),
    /// The Name is [`Name::Digest`].
    Digest(Handle, TpmtHa<'a>),
}

impl<'a> EntityHandle<'a> {
    pub const NULL: Self = Self::Handle(Handle::RH_NULL);
    pub const OWNER: Self = Self::Handle(Handle::RH_OWNER);
    pub const PLATFORM: Self = Self::Handle(Handle::RH_PLATFORM);
    pub const ENDORSEMENT: Self = Self::Handle(Handle::RH_ENDORSEMENT);

    pub const fn handle(&self) -> Handle {
        match *self {
            Self::Empty(h) | Self::Handle(h) | Self::Digest(h, _) => h,
        }
    }

    pub const fn name(&self) -> Name<'a> {
        match *self {
            Self::Empty(_) => Name::Empty,
            Self::Handle(h) => Name::Handle(h),
            Self::Digest(_, d) => Name::Digest(d),
        }
    }
}

impl From<SequenceHandle> for EntityHandle<'_> {
    fn from(h: SequenceHandle) -> Self {
        Self::Empty(h.0)
    }
}
impl<'a> From<NvHandle<'a>> for EntityHandle<'a> {
    fn from(h: NvHandle<'a>) -> Self {
        Self::Digest(h.index, h.digest)
    }
}
impl<'a> From<ObjectHandle<'a>> for EntityHandle<'a> {
    fn from(h: ObjectHandle<'a>) -> Self {
        match h.digest {
            Some(d) => Self::Digest(h.handle, d),
            None => Self::Empty(h.handle),
        }
    }
}

// The conversions back check only the form of the Name, not the handle range.
impl TryFrom<EntityHandle<'_>> for Handle {
    type Error = UnmarshalError;
    fn try_from(h: EntityHandle<'_>) -> Result<Self, UnmarshalError> {
        match h {
            EntityHandle::Handle(h) => Ok(h),
            _ => Err(UnmarshalError),
        }
    }
}
impl TryFrom<EntityHandle<'_>> for SequenceHandle {
    type Error = UnmarshalError;
    fn try_from(h: EntityHandle<'_>) -> Result<Self, UnmarshalError> {
        match h {
            EntityHandle::Empty(h) => Ok(Self(h)),
            _ => Err(UnmarshalError),
        }
    }
}
impl<'a> TryFrom<EntityHandle<'a>> for NvHandle<'a> {
    type Error = UnmarshalError;
    fn try_from(h: EntityHandle<'a>) -> Result<Self, UnmarshalError> {
        match h {
            EntityHandle::Digest(index, digest) => Ok(Self { index, digest }),
            _ => Err(UnmarshalError),
        }
    }
}
impl<'a> TryFrom<EntityHandle<'a>> for ObjectHandle<'a> {
    type Error = UnmarshalError;
    fn try_from(h: EntityHandle<'a>) -> Result<Self, UnmarshalError> {
        match h {
            EntityHandle::Empty(handle) => Ok(Self {
                handle,
                digest: None,
            }),
            EntityHandle::Digest(handle, d) => Ok(Self {
                handle,
                digest: Some(d),
            }),
            EntityHandle::Handle(_) => Err(UnmarshalError),
        }
    }
}

#[cfg(all(test, feature = "sha256"))]
mod tests {
    use super::*;
    use crate::commands::{NVRead, responses};
    use crate::{Command, Response, UnmarshalCommand, UnmarshalResponse};

    const DIGEST: [u8; 32] = [7; 32];
    const NV: NvHandle<'static> = NvHandle {
        index: Handle(0x0150_0001),
        digest: TpmtHa::Sha256(&DIGEST),
    };

    fn round_trip(name: Name<'_>, bare: &[u8]) {
        let mut buf = [0u8; TpmtHa::MAX_SIZE];
        assert_eq!(name.bytes(&mut buf), bare);
        let mut wire = [0u8; Name::MAX_SIZE];
        let n = name.marshal(&mut wire);
        assert_eq!(wire[..2], (bare.len() as u16).to_be_bytes());
        assert_eq!(&wire[2..n], bare);
        let mut src = &wire[..n];
        assert_eq!(Name::unmarshal(&mut src), Ok(name));
        assert!(src.is_empty());
    }

    #[test]
    fn name_encoding() {
        round_trip(Name::Empty, &[]);
        round_trip(Name::Handle(Handle::RH_OWNER), &[0x40, 0, 0, 1]);
        let mut bare = [7u8; 34];
        bare[..2].copy_from_slice(&[0x00, 0x0b]);
        round_trip(Name::Digest(TpmtHa::Sha256(&DIGEST)), &bare);
    }

    #[test]
    fn name_rejects_malformed() {
        let mut unknown_alg = [0u8; 36];
        unknown_alg[..4].copy_from_slice(&[0, 34, 0xff, 0xff]);
        let mut wrong_len = [0u8; 36];
        wrong_len[..4].copy_from_slice(&[0, 34, 0x00, 0x0c]); // SHA-384
        let bad: [&[u8]; 7] = [
            &[],
            &[0, 1],
            &[0, 3, 1, 2, 3],
            &[0, 4, 0x40, 0, 0],
            &[0, 6, 0x00, 0x0b, 1, 2, 3, 4],
            &unknown_alg,
            &wrong_len,
        ];
        for mut src in bad {
            assert!(Name::unmarshal(&mut src).is_err(), "{src:?}");
        }
    }

    #[test]
    fn entity_handle_conversions() {
        let seq = SequenceHandle(Handle(0x8000_0002));
        let obj = ObjectHandle {
            handle: Handle(0x8000_0001),
            digest: None,
        };
        let e = EntityHandle::from(seq);
        assert_eq!((e.handle(), e.name()), (seq.0, Name::Empty));
        assert!(SequenceHandle::try_from(e) == Ok(seq));
        let e = EntityHandle::from(obj);
        assert_eq!((e.handle(), e.name()), (obj.handle, Name::Empty));
        let e = EntityHandle::from(NV);
        assert_eq!((e.handle(), e.name()), (NV.index, Name::Digest(NV.digest)));
        assert_eq!(EntityHandle::OWNER.name(), Name::Handle(Handle::RH_OWNER));

        // Conversions back check the form of the Name.
        assert_eq!(Handle::try_from(EntityHandle::NULL), Ok(Handle::RH_NULL));
        assert!(Handle::try_from(EntityHandle::from(NV)).is_err());
        assert!(NvHandle::try_from(EntityHandle::from(obj)).is_err());
        assert!(ObjectHandle::try_from(EntityHandle::OWNER).is_err());
        assert!(SequenceHandle::try_from(EntityHandle::from(NV)).is_err());
    }

    #[test]
    fn command_and_response_handles() {
        let cmd = NVRead {
            auth_handle: EntityHandle::OWNER,
            nv_index: NV,
            size: 8,
            offset: 2,
        };
        let handles = cmd.handles();
        assert_eq!(handles.map(|h| h.handle()), [Handle::RH_OWNER, NV.index]);
        assert_eq!(
            handles.map(|h| h.name()),
            [Name::Handle(Handle::RH_OWNER), Name::Digest(NV.digest)]
        );

        let mut buf = [0u8; NVRead::MAX_SIZE];
        let n = cmd.marshal(&mut buf);
        let params = &buf[..n];
        let back = NVRead::unmarshal_with_handles(handles, &mut &params[..]).unwrap();
        assert_eq!(back.handles().map(|h| h.name()), handles.map(|h| h.name()));
        assert_eq!((back.size, back.offset), (8, 2));
        let wrong = [EntityHandle::OWNER, EntityHandle::OWNER];
        assert!(NVRead::unmarshal_with_handles(wrong, &mut &params[..]).is_err());

        let seq = Handle(0x8000_0005);
        let rsp = responses::HMACStart::unmarshal_with_handles([seq], &mut &[][..]).unwrap();
        assert!(rsp.sequence_handle == SequenceHandle(seq));
        assert_eq!(rsp.handles(), [seq]);
    }
}

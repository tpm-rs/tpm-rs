//! Handle wrappers for TPM 2.0 command handle areas and `cpHash` Name resolution.

use core::ops::Deref;

use crate::{Handle, Tpm2bName, TpmHt};

/// A TPM [`Handle`] paired with its optional [`Tpm2bName`] for session `cpHash`
/// computation.
///
/// Command handle-area slots that can accept an Object or NV Index use
/// `NamedHandle`. When `name` is `Some`, those bytes are used directly as the
/// handle's TPM Name (including an empty [`Tpm2bName`] for sequence objects or
/// external objects with `TPM_ALG_NULL` name algorithm). When `name` is `None`:
/// - For handle-named types ([`TpmHt::PCR`], [`TpmHt::HMACSession`],
///   [`TpmHt::PolicySession`], [`TpmHt::Permanent`], [`TpmHt::AC`]),
///   [`Self::resolve_name`] yields the 4-byte big-endian handle value.
/// - For Object and NV Index handles ([`TpmHt::Transient`],
///   [`TpmHt::Persistent`], [`TpmHt::NVIndex`], [`TpmHt::ExternalNV`],
///   [`TpmHt::PermanentNV`]), `None` indicates the Name was omitted (valid for
///   no-session commands, password authorization, and wire unmarshaling), and
///   [`Self::resolve_name`] returns `None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct NamedHandle<'a> {
    pub handle: Handle,
    pub name: Option<Tpm2bName<'a>>,
}

impl<'a> NamedHandle<'a> {
    /// Creates a [`NamedHandle`] with an explicit [`Tpm2bName`].
    pub const fn new(handle: Handle, name: Tpm2bName<'a>) -> Self {
        Self {
            handle,
            name: Some(name),
        }
    }

    /// Creates a [`NamedHandle`] without an explicit [`Tpm2bName`].
    pub const fn from_handle(handle: Handle) -> Self {
        Self { handle, name: None }
    }

    /// Resolves the raw Name bytes to hash into `cpHash`, or returns `None` if
    /// this handle requires an explicit digest Name that was not provided.
    pub fn resolve_name(&self) -> Option<HandleName<'a>> {
        if let Some(name) = self.name {
            return Some(HandleName::Name(name));
        }
        match self.handle.handle_type()? {
            TpmHt::PCR
            | TpmHt::HMACSession
            | TpmHt::PolicySession
            | TpmHt::Permanent
            | TpmHt::AC => Some(HandleName::Handle(self.handle.0.to_be_bytes())),
            TpmHt::NVIndex
            | TpmHt::ExternalNV
            | TpmHt::PermanentNV
            | TpmHt::Transient
            | TpmHt::Persistent => None,
        }
    }
}

impl From<Handle> for NamedHandle<'_> {
    fn from(handle: Handle) -> Self {
        Self::from_handle(handle)
    }
}

/// A TPM sequence object handle whose Name is always empty (`&[]`).
///
/// Returned by `*SequenceStart` commands and accepted by `SequenceUpdate` and
/// `*SequenceComplete` commands. Converting a `SequenceHandle` into a
/// [`NamedHandle`] sets `name` to an empty [`Tpm2bName`], matching Part 1,
/// Section 13 of the TPM 2.0 Specification.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(transparent)]
pub struct SequenceHandle(pub Handle);

impl From<Handle> for SequenceHandle {
    fn from(handle: Handle) -> Self {
        Self(handle)
    }
}

impl From<SequenceHandle> for Handle {
    fn from(handle: SequenceHandle) -> Self {
        handle.0
    }
}

impl From<SequenceHandle> for NamedHandle<'_> {
    fn from(handle: SequenceHandle) -> Self {
        Self::new(handle.0, Tpm2bName::default())
    }
}

/// Resolved TPM Name bytes for a [`NamedHandle`].
///
/// Returned by [`NamedHandle::resolve_name`]. Dereferences to `&[u8]` for
/// direct use in `cpHash` computation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HandleName<'a> {
    /// 4-byte big-endian handle Name (PCR, session, permanent, or AC handle).
    Handle([u8; 4]),
    /// Explicit Name buffer (digest Name for objects/NV indices, or empty for
    /// sequence / `TPM_ALG_NULL` external objects).
    Name(Tpm2bName<'a>),
}

impl HandleName<'_> {
    /// Returns the resolved Name bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Handle(bytes) => bytes,
            Self::Name(name) => name.as_slice(),
        }
    }
}

impl AsRef<[u8]> for HandleName<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for HandleName<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{
        EventSequenceComplete, Message, NVRead, ReadPublic, UnmarshalMessage, responses,
    };
    use crate::{Tpm2bMaxBuffer, Tpm2bName};

    #[test]
    fn resolve_name_handle_named_types() {
        let handles = [
            Handle(0x0000_0007), // PCR
            Handle(0x0200_0001), // HMACSession
            Handle(0x0300_0002), // PolicySession
            Handle::RH_OWNER,    // Permanent
            Handle::RH_NULL,     // Permanent (TPM_RH_NULL)
            Handle(0x9000_0001), // AC
        ];
        for h in handles {
            let nh = NamedHandle::from(h);
            assert_eq!(nh.handle, h);
            assert_eq!(nh.name, None);
            let resolved = nh.resolve_name().expect("handle-named type should resolve");
            let expected = h.0.to_be_bytes();
            assert_eq!(resolved, HandleName::Handle(expected));
            assert_eq!(&*resolved, &expected[..]);
            assert_eq!(resolved.as_ref(), &expected[..]);
        }
    }

    #[test]
    fn resolve_name_object_and_nv_require_explicit_name() {
        let handles = [
            Handle(0x0100_0001), // NVIndex
            Handle(0x1100_0001), // ExternalNV
            Handle(0x1200_0001), // PermanentNV
            Handle(0x8000_0000), // Transient
            Handle(0x8100_0001), // Persistent
            Handle(0xFF00_0000), // Unknown TpmHt
        ];
        for h in handles {
            assert_eq!(NamedHandle::from_handle(h).resolve_name(), None);
        }

        let name_bytes = [0x00, 0x0b, 0xde, 0xad, 0xbe, 0xef];
        let name = Tpm2bName::new(&name_bytes).unwrap();
        let nh = NamedHandle::new(Handle(0x8000_0000), name);
        let resolved = nh.resolve_name().unwrap();
        assert_eq!(resolved, HandleName::Name(name));
        assert_eq!(&*resolved, &name_bytes[..]);

        // Empty explicit name (e.g. LoadExternal with TPM_ALG_NULL nameAlg).
        let empty = NamedHandle::new(Handle(0x8000_0001), Tpm2bName::default());
        assert_eq!(&*empty.resolve_name().unwrap(), &[]);
    }

    #[test]
    fn sequence_handle_conversions_and_empty_name() {
        let raw = Handle(0x8000_0005);
        let seq = SequenceHandle::from(raw);
        assert_eq!(Handle::from(seq), raw);

        let nh = NamedHandle::from(seq);
        assert_eq!(nh.handle, raw);
        assert_eq!(nh.name, Some(Tpm2bName::default()));
        assert_eq!(&*nh.resolve_name().unwrap(), &[]);
    }

    #[test]
    fn command_handles_and_unmarshal_roundtrip() {
        let digest = Tpm2bName::new(&[0x00, 0x0b, 1, 2, 3, 4]).unwrap();
        let obj = NamedHandle::new(Handle(0x8000_0000), digest);

        // Unauthenticated Object handle still exposes its Name via Message::handles.
        let read_pub = ReadPublic { object_handle: obj };
        assert_eq!(ReadPublic::NUM_HANDLES, 1);
        assert_eq!(read_pub.handles(), [obj]);
        let mut empty: &[u8] = &[];
        let unmarshaled =
            ReadPublic::unmarshal_with_handles([Handle(0x8000_0000).into()], &mut empty).unwrap();
        assert_eq!(
            unmarshaled.object_handle,
            NamedHandle::from_handle(Handle(0x8000_0000))
        );

        // Mixed Handle + SequenceHandle command.
        let pcr = Handle(0x0000_0010);
        let seq = SequenceHandle(Handle(0x8000_0002));
        let ev = EventSequenceComplete {
            pcr_handle: pcr,
            sequence_handle: seq,
            buffer: Tpm2bMaxBuffer::new(&[0xaa]).unwrap(),
        };
        let [h0, h1] = ev.handles();
        assert_eq!(&*h0.resolve_name().unwrap(), &pcr.0.to_be_bytes()[..]);
        assert_eq!(&*h1.resolve_name().unwrap(), &[]);
        let mut param = &[0x00u8, 0x01, 0xaa][..];
        let ev2 =
            EventSequenceComplete::unmarshal_with_handles([pcr.into(), seq.0.into()], &mut param)
                .unwrap();
        assert_eq!(ev2, ev);

        // NVRead with permanent auth_handle + digest-named nv_index.
        let nv = NamedHandle::new(Handle(0x0140_0001), digest);
        let nv_read = NVRead {
            auth_handle: Handle::RH_OWNER.into(),
            nv_index: nv,
            size: 16,
            offset: 0,
        };
        let [auth_h, idx_h] = nv_read.handles();
        assert_eq!(
            &*auth_h.resolve_name().unwrap(),
            &Handle::RH_OWNER.0.to_be_bytes()[..]
        );
        assert_eq!(&*idx_h.resolve_name().unwrap(), digest.as_slice());

        // Response named_handle helpers.
        let load_rsp = responses::Load {
            object_handle: Handle(0x8000_0000),
            name: digest,
        };
        assert_eq!(load_rsp.named_handle(), obj);

        let load_ext_rsp = responses::LoadExternal {
            object_handle: Handle(0x8000_0000),
            name: Tpm2bName::default(),
        };
        assert_eq!(&*load_ext_rsp.named_handle().resolve_name().unwrap(), &[]);
    }
}

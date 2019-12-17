use byteorder::{ByteOrder, NetworkEndian as NE};

use core::num::NonZeroU16;
use core::{convert::TryFrom, u16};

use crate::error::ParseError;
use crate::{tag, Tag, TagIterator};

pub const PADI: u8 = 0x09;
pub const PADO: u8 = 0x07;
pub const PADR: u8 = 0x19;
pub const PADS: u8 = 0x65;
pub const PADT: u8 = 0xa7;

#[repr(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Code {
    Padi = PADI,
    Pado = PADO,
    Padr = PADR,
    Pads = PADS,
    Padt = PADT,
}

impl Code {
    fn try_from(code: u8) -> Result<Self, ParseError> {
        Ok(match code {
            PADI => Code::Padi,
            PADO => Code::Pado,
            PADR => Code::Padr,
            PADS => Code::Pads,
            PADT => Code::Padt,
            _ => return Err(ParseError::InvalidPppoeCode(code)),
        })
    }
}

#[derive(Debug)]
pub struct Header<'a>(&'a mut [u8]);

impl<'a> Header<'a> {
    pub fn from_buffer(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::from_buffer_with_code(buffer, None)
    }

    pub fn from_buffer_with_code(
        buffer: &mut [u8],
        expected_code: Option<Code>,
    ) -> Result<Header, ParseError> {
        Self::ensure_minimal_buffer_length(buffer)?;
        if buffer[0] != 0x11 {
            let version = buffer[0] >> 4;
            let r#type = buffer[0] & 0x0f;
            return if buffer[0] >> 4 != 1 {
                Err(ParseError::InvalidPppoeVersion(version))
            } else {
                Err(ParseError::InvalidPppoeType(r#type))
            };
        }

        let code = Code::try_from(buffer[1])?;
        if let Some(expected_code) = expected_code {
            if code != expected_code {
                return Err(ParseError::UnexpectedCode(code as u8));
            }
        }

        let length = usize::from(NE::read_u16(&buffer[4..]));
        if length + 6 > buffer.len() {
            return Err(ParseError::PayloadLengthOutOfBound {
                actual_packet_length: buffer.len() as u16,
                payload_length: length as u16,
            });
        } else if length == 0 {
            return Err(ParseError::MissingServiceName);
        }

        Self::validate_tags(&mut buffer[6..6 + length])?;

        Ok(Header(buffer))
    }

    pub fn padi_from_buffer(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::from_buffer_with_code(buffer, Some(Code::Padi))
    }

    pub fn pado_from_buffer(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::from_buffer_with_code(buffer, Some(Code::Pado))
    }

    pub fn padr_from_buffer(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::from_buffer_with_code(buffer, Some(Code::Padr))
    }

    pub fn pads_from_buffer(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::from_buffer_with_code(buffer, Some(Code::Pads))
    }

    pub fn padt_from_buffer(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::from_buffer_with_code(buffer, Some(Code::Padt))
    }

    fn ensure_minimal_buffer_length(buffer: &mut [u8]) -> Result<(), ParseError> {
        if buffer.len() < 6 {
            return Err(ParseError::BufferTooSmall(buffer.len()));
        }
        Ok(())
    }

    fn check_duplicate(tag: u16, exists: &mut bool) -> Result<(), ParseError> {
        if *exists {
            return Err(ParseError::DuplicateTag(tag));
        }

        *exists = true;
        Ok(())
    }

    pub(crate) fn validate_tags(mut payload: &[u8]) -> Result<(), ParseError> {
        let mut tag;
        let mut length;
        let total_packet_length = payload.len() as u16;

        // these tags must only exists once
        let mut service_name = false;
        let mut host_uniq = false;
        let mut ac_name = false;
        let mut relay_session_id = false;
        let mut ppp_max_payload = false;
        let mut ac_cookie = false;

        loop {
            match payload.len() {
                0 => {
                    return Ok(());
                }
                // tags must be at least 4 bytes
                x if x < 4 => {
                    return Err(ParseError::IncompleteTagAtPacketEnd {
                        total_packet_length,
                        left_over_bytes: x as u16,
                    });
                }

                total_length => {
                    tag = NE::read_u16(payload);

                    // check for duplicates
                    match tag {
                        tag::TAG_SERVICE_NAME => Self::check_duplicate(tag, &mut service_name)?,
                        tag::TAG_AC_NAME => Self::check_duplicate(tag, &mut ac_name)?,
                        tag::TAG_AC_COOKIE => Self::check_duplicate(tag, &mut ac_cookie)?,
                        tag::TAG_HOST_UNIQ => Self::check_duplicate(tag, &mut host_uniq)?,
                        tag::TAG_RELAY_SESSION_ID => {
                            Self::check_duplicate(tag, &mut relay_session_id)?
                        }
                        tag::TAG_PPP_MAX_PAYLOAD => {
                            Self::check_duplicate(tag, &mut ppp_max_payload)?
                        }
                        _ => (),
                    }

                    length = usize::from(NE::read_u16(&payload[2..]));
                    if tag == tag::TAG_END_OF_LIST {
                        break;
                    }

                    if length + 4 > total_length {
                        return Err(ParseError::TagLengthOutOfBound {
                            expected_tag_length: length as u16,
                            remaining_payload_length: total_length as u16,
                        });
                    };
                    payload = &payload[4 + length..]
                }
            }
        }

        // Found End-of-List tag, nothing should be behind this
        if length != 0 || payload.len() != 4 {
            return Err(ParseError::DataBehindEolTag);
        }

        if !service_name {
            return Err(ParseError::MissingServiceName);
        }

        Ok(())
    }

    pub fn code(&self) -> u8 {
        self.0[1]
    }

    pub fn set_code(&mut self, code: Code) {
        self.0[1] = code as u8;
    }

    pub fn session_id(&self) -> u16 {
        NE::read_u16(&self.0[2..])
    }

    pub fn len(&self) -> usize {
        usize::from(6 + NE::read_u16(&self.0[4..]))
    }

    unsafe fn set_len(&mut self, new_length: u16) {
        NE::write_u16(&mut self.0[4..], new_length)
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[6..]
    }

    pub fn clear_payload(&mut self) {
        //  NE::write_u16(&mut self.0[4..], 0)
        unsafe { self.set_len(0) };
    }

    pub fn clear_eol(&mut self) {
        if Some(tag::Tag::EndOfList) == self.tag_iter().last() {
            unsafe { self.set_len(self.len() as u16 - 10) }
        }
    }

    pub fn create_packet(
        buffer: &mut [u8],
        code: Code,
        session_id: u16,
    ) -> Result<Header, ParseError> {
        Self::ensure_minimal_buffer_length(buffer)?;

        // set version and type
        buffer[0] = 0x11;
        buffer[1] = code as u8;
        NE::write_u16(&mut buffer[2..], session_id);
        NE::write_u16(&mut buffer[4..], 0);

        Ok(Header(buffer))
    }

    pub fn create_padi(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::create_packet(buffer, Code::Padi, 0)
    }

    pub fn create_pado(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::create_packet(buffer, Code::Pado, 0)
    }

    pub fn create_padr(buffer: &mut [u8]) -> Result<Header, ParseError> {
        Self::create_packet(buffer, Code::Padr, 0)
    }

    pub fn create_pads(buffer: &mut [u8], session_id: NonZeroU16) -> Result<Header, ParseError> {
        Self::create_packet(buffer, Code::Pads, u16::from(session_id))
    }

    pub fn create_padt(buffer: &mut [u8], session_id: NonZeroU16) -> Result<Header, ParseError> {
        Self::create_packet(buffer, Code::Padt, u16::from(session_id))
    }

    pub fn create_padr_from_pado(
        buffer: &'a mut [u8],
        pado: &Self,
        expected_service_name: Option<&[u8]>,
        expected_ac_name: Option<&[u8]>,
    ) -> Result<Header<'a>, ParseError> {
        let mut padr = Self::create_padr(buffer)?;

        let mut tag_iterator = pado.tag_iter();

        let mut has_service_name = false;
        let mut has_system_name = false;

        for tag in tag_iterator.by_ref() {
            match &tag {
                Tag::ServiceName(service_name) => {
                    if let Some(expected_service_name) = expected_service_name {
                        if service_name != &expected_service_name {
                            return Err(ParseError::ServiceNameMismatch);
                        }
                    }
                    has_service_name = true;
                    padr.add_tag(tag)?;
                }

                Tag::AcName(system_name) => {
                    if let Some(expected_system_name) = expected_ac_name {
                        if system_name != &expected_system_name {
                            return Err(ParseError::AcNameMismatch);
                        }
                    }
                    has_system_name = true;
                }

                Tag::RelaySessionId(_) | Tag::AcCookie(_) => {
                    padr.add_tag(tag)?;
                }

                _ => (),
            };
        }

        if !has_service_name {
            return Err(ParseError::MissingServiceName);
        }
        if !has_system_name {
            return Err(ParseError::MissingAcName);
        }

        Ok(padr)
    }

    pub fn tag_iter(&self) -> TagIterator {
        TagIterator {
            payload: &self.0[6..self.len()],
        }
    }

    pub fn add_tag(&mut self, tag: Tag) -> Result<(), ParseError> {
        let packet_length = self.len();

        let tag_length = tag.write(&mut self.0[packet_length..])?;
        unsafe { self.set_len((packet_length - 6 + tag_length) as u16) };
        Ok(())
    }

    pub fn add_vendor_tag_with_callback<F>(&mut self, callback: F) -> Result<(), ParseError>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, ParseError>,
    {
        let packet_length = self.len();
        let buffer_length = self.0.len();

        let payload_end = &mut self.0[packet_length..];

        let vendor_tag_length = callback(&mut payload_end[4..])?;
        NE::write_u16(payload_end, tag::TAG_VENDOR_SPECIFIC);
        NE::write_u16(&mut payload_end[2..], vendor_tag_length as u16);

        unsafe { self.set_len((packet_length - 6 + vendor_tag_length + 4) as u16) };

        Ok(())
    }

    pub fn add_end_tag(&mut self) -> Result<(), ParseError> {
        self.add_tag(Tag::EndOfList)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    pub fn get_ref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn get_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for Header<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> Into<&'a [u8]> for Header<'a> {
    fn into(self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::u8;

    macro_rules! create_tags {
        ($content:expr, $($tag:path),* $(,)? ) => {{
            let mut vec = Vec::new();
            $(
                let tag = $tag($content);
                let id = tag.get_tag_type();
                vec.push((id, tag));
            )*
            vec
        }}
    }

    fn minimal_header<'a>(buffer: &'a mut [u8], service_name: Option<&[u8]>) -> Header<'a> {
        let mut header = Header::create_padi(&mut buffer[..]).unwrap();
        if let Some(service_name) = service_name {
            header.add_tag(Tag::ServiceName(service_name)).unwrap();
        } else {
            header.add_tag(Tag::ServiceName(b"")).unwrap();
        }
        header
    }

    fn minimal_header_with_eol<'a>(
        buffer: &'a mut [u8],
        service_name: Option<&[u8]>,
    ) -> Header<'a> {
        let mut header = minimal_header(buffer, service_name);
        header.add_tag(Tag::EndOfList).unwrap();
        header
    }

    fn expect_parse_error(buffer: &mut [u8]) -> ParseError {
        let should_be_error = Header::from_buffer(&mut buffer[..]);
        assert!(should_be_error.is_err());
        should_be_error.unwrap_err()
    }

    #[test]
    fn duplicate_tag_detection() {
        let buffer = &mut [0u8; 200];
        let content = b"abcdef123";
        let tags = create_tags!(
            content,
            Tag::ServiceName,
            Tag::AcName,
            Tag::HostUniq,
            Tag::RelaySessionId,
        );

        for (id, tag) in tags {
            let mut header = Header::create_padi(buffer).unwrap();
            header.add_tag(tag).unwrap();
            header.add_tag(tag).unwrap();

            let err = expect_parse_error(buffer);
            assert_eq!(err, ParseError::DuplicateTag(id));
        }
    }

    #[test]
    fn reported_length_bigger_than_packet() {
        let buffer = &mut [0u8; 200];
        let mut header = minimal_header_with_eol(buffer, None);
        unsafe { header.set_len(555) };

        let err = expect_parse_error(buffer);
        assert!(match err {
            ParseError::PayloadLengthOutOfBound { .. } => true,
            _ => false,
        });
    }

    #[test]
    fn buffer_less_than_minimal_required_size_for_parsing() {
        let buffer = &mut [0u8; 4];
        let err = expect_parse_error(buffer);
        assert!(match err {
            ParseError::BufferTooSmall(_) => true,
            _ => false,
        });
    }

    #[test]
    fn buffer_less_than_minimal_required_size_for_creation() {
        let buffer = &mut [0u8; 4];
        assert!(Header::create_padi(buffer).is_err());
    }

    #[test]
    fn invalid_pppoe_version() {
        let buffer = &mut [0u8; 20];
        let err = expect_parse_error(buffer);
        assert!(match err {
            ParseError::InvalidPppoeVersion(_) => true,
            _ => false,
        })
    }

    #[test]
    fn invalid_pppoe_type() {
        let buffer = &mut [0u8; 20];
        buffer[0] = 0x01 << 4;
        let err = expect_parse_error(buffer);
        assert!(match err {
            ParseError::InvalidPppoeType(_) => true,
            _ => false,
        });
    }

    #[test]
    fn invalid_pppoe_code() {
        let buffer = &mut [0u8; 20];
        minimal_header(buffer, None);
        for code in 0..=u8::MAX {
            buffer[1] = code;
            match code {
                PADI | PADO | PADR | PADS | PADT => continue,
                _ => {
                    let err = expect_parse_error(buffer);
                    assert!(match err {
                        ParseError::InvalidPppoeCode(_) => true,
                        _ => false,
                    });
                }
            }
        }
    }

    #[test]
    fn missing_service_name() {
        let buffer = &mut [0u8; 20];
        buffer[0] = 0x11;
        buffer[1] = PADI;
        let err = expect_parse_error(buffer);
        assert!(match err {
            ParseError::MissingServiceName => true,
            _ => false,
        });

        Header::create_padi(buffer).unwrap().add_tag(Tag::EndOfList);

        let err = expect_parse_error(buffer);
        assert!(match err {
            ParseError::MissingServiceName => true,
            _ => false,
        });
    }

    #[test]
    fn pppoe_code_conditional_parsing() {
        let buffer = &mut [0u8; 200];
        let codes = [Code::Padi, Code::Pado, Code::Padr, Code::Pads, Code::Padt];
        let session_ids = [0, 0, 0, 1, 1];

        for (i, code) in codes.iter().cloned().enumerate() {
            Header::create_packet(buffer, code, session_ids[i])
                .unwrap()
                .add_tag(Tag::ServiceName(b"abc"))
                .unwrap();
            for (j, code) in codes.iter().cloned().enumerate() {
                let header = Header::from_buffer_with_code(buffer, Some(code));
                if j == i {
                    assert!(header.is_ok())
                } else {
                    assert!(header.is_err())
                }
            }
        }
    }
}

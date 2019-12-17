use byteorder::{ByteOrder, NetworkEndian as NE};

use core::{convert::TryFrom, num, str, u16};

use crate::error::ParseError;

// RFC 2516
pub const TAG_END_OF_LIST: u16 = 0x0000;
pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;
pub const TAG_VENDOR_SPECIFIC: u16 = 0x0105;
pub const TAG_RELAY_SESSION_ID: u16 = 0x0110;
pub const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
pub const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
pub const TAG_GENERIC_ERROR: u16 = 0x0203;

// RFC 4638
pub const TAG_PPP_MAX_PAYLOAD: u16 = 0x0120;

// RFC 5578
pub const TAG_CREDITS: u16 = 0x0106;
pub const TAG_METRICS: u16 = 0x0107;
pub const TAG_SEQUENCE_NUMBER: u16 = 0x0108;
pub const TAG_CREDIT_SCALE_FACTOR: u16 = 0x0109;

#[derive(Debug, PartialEq, Eq)]
pub enum Tag<'a> {
    EndOfList,
    ServiceName(&'a [u8]),
    AcName(&'a [u8]),
    HostUniq(&'a [u8]),
    AcCookie(&'a [u8]),
    VendorSpecific(&'a [u8]),
    RelaySessionId(&'a [u8]),
    ServiceNameError(&'a [u8]),
    AcSystemError(&'a [u8]),
    GenericError(&'a [u8]),
    // RFC 4639
    PppMaxMtu(u16),
    // RFC 5578
    Credits((u16, u16)),
    // TODO: this field requires a little logic
    Metrics(&'a [u8]),
    SequenceNumber(u16),
    CreditScaleFactor(u16),
    // Unknown
    Unknown((num::NonZeroU16, &'a [u8])),
}

impl<'a> Tag<'a> {
    pub fn from_buffer(buffer: &[u8]) -> Result<(Tag, &[u8]), ParseError> {
        let total_length = buffer.len();
        if total_length < 4 {
            return Err(ParseError::IncompleteTag(total_length as u8));
        }

        let tag = NE::read_u16(buffer);
        let length = usize::from(NE::read_u16(&buffer[2..])) + 4;

        if length > total_length {
            return Err(ParseError::TagLengthOutOfBound {
                expected_tag_length: length as u16,
                remaining_payload_length: total_length as u16,
            });
        }

        let tag_enum = match tag {
            TAG_END_OF_LIST => {
                if length != 4 {
                    return Err(ParseError::TagWithInvalidLength {
                        tag_type: TAG_END_OF_LIST,
                        length: length as u16,
                    });
                }
                Tag::EndOfList
            }
            TAG_SERVICE_NAME => Tag::ServiceName(&buffer[4..length]),
            TAG_AC_NAME => Tag::AcName(&buffer[4..length]),
            TAG_HOST_UNIQ => Tag::HostUniq(&buffer[4..length]),
            TAG_AC_COOKIE => Tag::AcCookie(&buffer[4..length]),
            TAG_VENDOR_SPECIFIC => Tag::VendorSpecific(&buffer[4..length]),
            TAG_RELAY_SESSION_ID => Tag::RelaySessionId(&buffer[4..length]),
            TAG_SERVICE_NAME_ERROR => Tag::ServiceNameError(&buffer[4..length]),
            TAG_AC_SYSTEM_ERROR => Tag::AcSystemError(&buffer[4..length]),
            TAG_GENERIC_ERROR => Tag::GenericError(&buffer[4..length]),

            TAG_PPP_MAX_PAYLOAD => {
                if length != 6 {
                    return Err(ParseError::TagWithInvalidLength {
                        tag_type: TAG_PPP_MAX_PAYLOAD,
                        length: length as u16,
                    });
                }
                Tag::PppMaxMtu(NE::read_u16(&buffer[4..]))
            }

            TAG_CREDITS => {
                if length != 8 {
                    return Err(ParseError::TagWithInvalidLength {
                        tag_type: TAG_PPP_MAX_PAYLOAD,
                        length: length as u16,
                    });
                }
                Tag::Credits((NE::read_u16(&buffer[4..]), NE::read_u16(&buffer[6..])))
            }
            TAG_SEQUENCE_NUMBER => {
                if length != 6 {
                    return Err(ParseError::TagWithInvalidLength {
                        tag_type: TAG_SEQUENCE_NUMBER,
                        length: length as u16,
                    });
                }
                Tag::SequenceNumber(NE::read_u16(&buffer[4..]))
            }
            TAG_CREDIT_SCALE_FACTOR => {
                if length != 6 {
                    return Err(ParseError::TagWithInvalidLength {
                        tag_type: TAG_CREDIT_SCALE_FACTOR,
                        length: length as u16,
                    });
                }
                Tag::CreditScaleFactor(NE::read_u16(&buffer[4..]))
            }
            // TODO: parsing this is more complex, check RFC for fields
            TAG_METRICS => Tag::Metrics(&buffer[4..length]),
            // everything else
            _ => Tag::Unknown((
                num::NonZeroU16::new(tag as u16).unwrap(),
                &buffer[4..length],
            )),
        };

        Ok((tag_enum, &buffer[length..]))
    }

    pub fn get_tag_type(&self) -> u16 {
        match self {
            Tag::EndOfList => TAG_END_OF_LIST,
            Tag::ServiceName(_) => TAG_SERVICE_NAME,
            Tag::AcName(_) => TAG_AC_NAME,
            Tag::HostUniq(_) => TAG_HOST_UNIQ,
            Tag::AcCookie(_) => TAG_AC_COOKIE,
            Tag::VendorSpecific(_) => TAG_VENDOR_SPECIFIC,
            Tag::RelaySessionId(_) => TAG_RELAY_SESSION_ID,
            Tag::ServiceNameError(_) => TAG_SERVICE_NAME_ERROR,
            Tag::AcSystemError(_) => TAG_AC_SYSTEM_ERROR,
            Tag::GenericError(_) => TAG_GENERIC_ERROR,
            Tag::PppMaxMtu(_) => TAG_PPP_MAX_PAYLOAD,
            Tag::Credits(_) => TAG_CREDITS,
            Tag::Metrics(_) => TAG_METRICS,
            Tag::SequenceNumber(_) => TAG_SEQUENCE_NUMBER,
            Tag::CreditScaleFactor(_) => TAG_CREDIT_SCALE_FACTOR,
            Tag::Unknown((tag, _)) => u16::from(*tag),
        }
    }

    pub fn get_message(&self) -> Result<Option<&str>, str::Utf8Error> {
        match self {
            Tag::EndOfList => Ok(None),
            Tag::ServiceName(msg)
            | Tag::AcName(msg)
            | Tag::HostUniq(msg)
            | Tag::AcCookie(msg)
            | Tag::VendorSpecific(msg)
            | Tag::RelaySessionId(msg)
            | Tag::ServiceNameError(msg)
            | Tag::AcSystemError(msg)
            | Tag::GenericError(msg)
            | Tag::Unknown((_, msg)) => {
                str::from_utf8(msg).map(|msg| if msg.len() == 0 { None } else { Some(msg) })
            }
            _ => Ok(None),
        }
    }

    pub fn get_tuple(&self) -> (u16, &[u8]) {
        match self {
            Tag::EndOfList => (TAG_END_OF_LIST, &[]),
            Tag::ServiceName(msg) => (TAG_SERVICE_NAME, msg),
            Tag::AcName(msg) => (TAG_AC_NAME, msg),
            Tag::HostUniq(msg) => (TAG_HOST_UNIQ, msg),
            Tag::AcCookie(msg) => (TAG_AC_COOKIE, msg),
            Tag::VendorSpecific(msg) => (TAG_VENDOR_SPECIFIC, msg),
            Tag::RelaySessionId(msg) => (TAG_RELAY_SESSION_ID, msg),
            Tag::ServiceNameError(msg) => (TAG_SERVICE_NAME_ERROR, msg),
            Tag::AcSystemError(msg) => (TAG_AC_SYSTEM_ERROR, msg),
            Tag::GenericError(msg) => (TAG_GENERIC_ERROR, msg),
            Tag::Unknown((num, msg)) => (u16::from(*num), msg),
            // RFC 5578 fucks with my logic
            _ => unimplemented!(),
        }
    }

    pub fn write(&self, buffer: &mut [u8]) -> Result<usize, ParseError> {
        match self {
            Tag::PppMaxMtu(mtu) => {
                if buffer.len() < 6 {
                    return Err(ParseError::BufferTooSmallForTag {
                        available: u16::try_from(buffer.len()).unwrap_or(u16::MAX),
                        requested: 6,
                    });
                }
                NE::write_u16(buffer, TAG_PPP_MAX_PAYLOAD);
                NE::write_u16(&mut buffer[2..], 2);
                NE::write_u16(&mut buffer[4..], *mtu);
                return Ok(6);
            }
            // TODO: handle RFC 5578 Tags
            _ => (),
        }

        let (tag_id, tag_content) = self.get_tuple();
        if buffer.len() < tag_content.len() + 4 {
            return Err(ParseError::BufferTooSmallForTag {
                available: buffer.len() as u16,
                requested: tag_content.len(),
            });
        }

        NE::write_u16(buffer, tag_id);
        NE::write_u16(&mut buffer[2..], tag_content.len() as u16);
        buffer[4..4 + tag_content.len()].copy_from_slice(tag_content);

        Ok(4 + tag_content.len())
    }
}

pub struct TagIterator<'a> {
    pub(crate) payload: &'a [u8],
}

impl<'a> Iterator for TagIterator<'a> {
    type Item = Tag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.len() == 0 {
            return None;
        }

        // buffer should be already validated at this point
        let (tag, payload) = Tag::from_buffer(self.payload).unwrap();
        self.payload = payload;
        Some(tag)
    }
}

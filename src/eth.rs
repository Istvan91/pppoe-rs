use byteorder::{ByteOrder, NetworkEndian as NE};

use std::convert::TryInto;

use crate::error::ParseError;

#[derive(Debug)]
pub struct Header<'a>(&'a mut [u8]);

impl<'a> Header<'a> {
    pub fn from_buffer(buffer: &'a mut [u8]) -> Result<Self, ParseError> {
        if buffer.len() < 14 {
            return Err(ParseError::BufferTooSmall(buffer.len()));
        }

        Ok(Self(buffer))
    }

    pub fn src_address(&self) -> &[u8; 6] {
        (&self.0[6..12]).try_into().unwrap()
    }

    pub fn set_src_address(&mut self, addr: &[u8; 6]) {
        self.0[6..12].copy_from_slice(addr);
    }

    pub fn dst_address(&self) -> &[u8; 6] {
        (&self.0[..6]).try_into().unwrap()
    }

    pub fn set_dst_address(&mut self, addr: &[u8; 6]) {
        self.0[..6].copy_from_slice(addr);
    }

    pub fn ether_type(&self) -> u16 {
        NE::read_u16(&self.0[12..])
    }

    pub fn set_ether_type(&mut self, ether_type: u16) {
        NE::write_u16(&mut self.0[12..], ether_type);
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[14..]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[14..]
    }
}

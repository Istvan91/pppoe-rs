use crate::error::*;
use crate::{self as pppoe, eth};

use std::slice;

pub const PPPOE_DISCOVERY: u16 = 0x8863;
pub const PPPOE_SESSION: u16 = 0x8864;

#[derive(Debug)]
pub struct Packet<'a> {
    ethernet: eth::Header<'a>,
    pppoe: pppoe::Header<'a>,
}

impl<'a> Packet<'a> {
    pub fn from_buffer(buffer: &'a mut [u8]) -> Result<Self, Error> {
        Self::ensure_minimal_buffer_size(buffer)?;
        let (eth_buf, pppoe_buf) = buffer.split_at_mut(14);

        Ok(Self {
            ethernet: eth::Header::from_buffer(eth_buf)?,
            pppoe: pppoe::Header::from_buffer(pppoe_buf)?,
        })
    }

    fn ensure_minimal_buffer_size(buffer: &mut [u8]) -> Result<(), ParseError> {
        // minimal eth + pppoe header size
        if buffer.len() < 20 {
            return Err(ParseError::BufferTooSmall(buffer.len()).into());
        }
        Ok(())
    }

    pub fn new_discovery_packet(
        buffer: &'a mut [u8],
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) -> Result<Self, Error> {
        Self::ensure_minimal_buffer_size(buffer)?;

        let (eth_buf, pppoe_buf) = buffer.split_at_mut(14);
        let mut ethernet = eth::Header::from_buffer(eth_buf)?;
        ethernet.set_src_address(src_mac);
        ethernet.set_dst_address(dst_mac);
        ethernet.set_ether_type(PPPOE_DISCOVERY);

        Ok(Self {
            ethernet,
            pppoe: pppoe::Header::create_padi(pppoe_buf)?,
        })
    }

    pub fn pppoe_header(&self) -> &pppoe::Header {
        &self.pppoe
    }

    pub fn pppoe_header_mut(&mut self) -> &mut pppoe::Header<'a> {
        &mut self.pppoe
    }

    pub fn ethernet_header(&self) -> &eth::Header {
        &self.ethernet
    }

    pub fn ethernet_header_mut(&mut self) -> &mut eth::Header<'a> {
        &mut self.ethernet
    }

    pub fn len(&self) -> usize {
        14 + self.pppoe.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.ethernet.dst_address().as_ptr();
        unsafe { slice::from_raw_parts(ptr, self.len()) }
    }
}

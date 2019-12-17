use crate::error::*;
use crate::{self as pppoe, eth};

use std::slice;

pub const PPPOE_DISCOVERY: u16 = 0x8863;
pub const PPPOE_SESSION: u16 = 0x8864;

fn ensure_minimal_buffer_size(buffer: &mut [u8]) -> Result<(), ParseError> {
    // minimal eth + pppoe header size
    if buffer.len() < 20 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

#[derive(Debug)]
pub struct Packet<'a> {
    ethernet: eth::Header<'a>,
    pppoe: pppoe::Header<'a>,
}

impl<'a> Packet<'a> {
    pub fn with_buffer(buffer: &'a mut [u8]) -> Result<Self, Error> {
        ensure_minimal_buffer_size(buffer)?;
        let (eth_buf, pppoe_buf) = buffer.split_at_mut(14);

        Ok(Self {
            ethernet: eth::Header::with_buffer(eth_buf)?,
            pppoe: pppoe::Header::with_buffer(pppoe_buf)?,
        })
    }

    pub fn pppoe_header(&self) -> &pppoe::Header {
        &self.pppoe
    }

    pub fn ethernet_header(&self) -> &eth::Header<'a> {
        &self.ethernet
    }

    pub fn len(&self) -> usize {
        14 + self.pppoe.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.ethernet.dst_address().as_ptr();
        unsafe { slice::from_raw_parts(ptr, self.len()) }
    }
}

pub struct PacketBuilder<'a> {
    ethernet: eth::HeaderBuilder<'a>,
    pppoe: pppoe::HeaderBuilder<'a>,
}

impl<'a> PacketBuilder<'a> {
    pub fn new_discovery_packet(
        buffer: &'a mut [u8],
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) -> Result<Self, Error> {
        ensure_minimal_buffer_size(buffer)?;

        let (eth_buf, pppoe_buf) = buffer.split_at_mut(14);
        let mut ethernet = eth::HeaderBuilder::with_buffer(eth_buf)?;
        ethernet.set_src_address(src_mac);
        ethernet.set_dst_address(dst_mac);
        ethernet.set_ether_type(PPPOE_DISCOVERY);

        Ok(Self {
            ethernet,
            pppoe: pppoe::HeaderBuilder::create_padi(pppoe_buf)?,
        })
    }

    pub fn len(&self) -> usize {
        14 + self.pppoe.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn pppoe_header(&mut self) -> &mut pppoe::HeaderBuilder<'a> {
        &mut self.pppoe
    }

    pub fn ethernet_header(&mut self) -> &mut eth::HeaderBuilder<'a> {
        &mut self.ethernet
    }

    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.ethernet.as_bytes().as_ptr();
        unsafe { slice::from_raw_parts(ptr, self.len()) }
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        let ptr = self.ethernet.as_mut_bytes().as_mut_ptr();
        // TODO: this could be undefined behaviour... need to check
        unsafe { slice::from_raw_parts_mut(ptr, self.len()) }
    }

    pub fn build(self) -> Result<Packet<'a>, Error> {
        Ok(Packet {
            ethernet: self.ethernet.build()?,
            pppoe: self.pppoe.build()?,
        })
    }
}

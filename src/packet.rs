use crate::error::*;
use crate::{self as pppoe, eth};

use std::slice;

pub const PPPOE_DISCOVERY: u16 = 0x8863;
pub const PPPOE_SESSION: u16 = 0x8864;

fn ensure_minimal_buffer_size(buffer: &[u8]) -> Result<(), ParseError> {
    // minimal eth + pppoe header size
    if buffer.len() < 20 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

/// A (valid) PPPoE Packet
#[derive(Debug)]
pub struct Packet<'a> {
    ethernet: eth::Header<'a>,
    pppoe: pppoe::Header<'a>,
}

impl<'a> Packet<'a> {
    /// Create a PPPoE from a buffer.
    ///
    /// The buffer is expected contain a valid Ethernet Packet (with an ethertype for PPPoE) and a
    /// PPPoE Packet.  Therefore the buffer must be greater than 20 bytes.
    pub fn with_buffer(buffer: &'a [u8]) -> Result<Self, Error> {
        ensure_minimal_buffer_size(buffer)?;
        let (eth_buf, pppoe_buf) = buffer.split_at(14);

        Ok(Self {
            ethernet: eth::Header::with_buffer(eth_buf)?,
            pppoe: pppoe::Header::with_buffer(pppoe_buf)?,
        })
    }

    /// Get the PPPoE Header from the Packet
    pub fn pppoe_header(&self) -> &pppoe::Header {
        &self.pppoe
    }

    /// Get the Ethernet Header from the Packet
    pub fn ethernet_header(&self) -> &eth::Header<'a> {
        &self.ethernet
    }

    /// Get the total Packet length
    pub fn len(&self) -> usize {
        14 + self.pppoe.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the Packet in byte representation.  The slice is a valid PPPoE Packet and can be send
    /// over an (raw) socket.
    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.ethernet.dst_address().as_ptr();
        unsafe { slice::from_raw_parts(ptr, self.len()) }
    }
}

/// A Builder to create PPPoE Packets
///
/// The Builder is directly using the supplied buffer.  It is therefore possible to create
/// incomplete or maleformed PPPoE Packets.
pub struct PacketBuilder<'a> {
    ethernet: eth::HeaderBuilder<'a>,
    pppoe: pppoe::HeaderBuilder<'a>,
}

impl<'a> PacketBuilder<'a> {
    /// Create a new PPPoE PADI
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

    /// Get the Packet Length
    pub fn len(&self) -> usize {
        14 + self.pppoe.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the PPPoE Header from the Packet
    pub fn pppoe_header(&mut self) -> &mut pppoe::HeaderBuilder<'a> {
        &mut self.pppoe
    }

    /// Get the Ethernet Header from the Packet
    pub fn ethernet_header(&mut self) -> &mut eth::HeaderBuilder<'a> {
        &mut self.ethernet
    }

    /// Get the Packet in byte representation.  The slice is a valid PPPoE Packet and can be send
    /// over an (raw) socket.
    ///
    /// The byte representation could be an incomplete or maleformed PPPoE Packet. If a correct
    /// packet should be send, consider calling `build` to validate the current Packet and use the
    /// resulting Packet instead of this builder.
    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.ethernet.as_bytes().as_ptr();
        unsafe { slice::from_raw_parts(ptr, self.len()) }
    }

    /// Get the Packet in byte representation.  The slice is a valid PPPoE Packet and can be send
    /// over an (raw) socket.
    ///
    /// This function can be used to directly access the underlying buffer mutable. Only useful for
    /// to deliberately corrupting PPPoE Packets.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        let ptr = self.ethernet.as_mut_bytes().as_mut_ptr();
        // TODO: this could be undefined behaviour... need to check
        unsafe { slice::from_raw_parts_mut(ptr, self.len()) }
    }

    /// validate the currently build Packet and return a `Packet` on success.
    pub fn build(self) -> Result<Packet<'a>, Error> {
        Ok(Packet {
            ethernet: self.ethernet.build()?,
            pppoe: self.pppoe.build()?,
        })
    }
}

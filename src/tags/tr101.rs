use crate::{error::ParseError, Tag, TagIterator};
use byteorder::{ByteOrder, NetworkEndian as NE};
use core::convert::TryFrom;
use core::{str, u16};

const BROADBAND_FORUM_VENDOR_ID: u32 = 0x0DE9;

// TAG TLS - defined in TR101
const AGENT_CIRCUIT_ID: u8 = 0x01;
const AGENT_REMOTE_ID: u8 = 0x02;
const ACTUAL_DATA_RATE_UP: u8 = 0x81;
const ACTUAL_DATA_RATE_DOWN: u8 = 0x82;
const MINIMUM_DATA_RATE_UP: u8 = 0x83;
const MINIMUM_DATA_RATE_DOWN: u8 = 0x84;
const ATTAINABLE_DATA_RATE_UP: u8 = 0x85;
const ATTAINABLE_DATA_RATE_DOWN: u8 = 0x86;
const MAXIMUM_DATA_RATE_UP: u8 = 0x87;
const MAXIMUM_DATA_RATE_DOWN: u8 = 0x88;
const MINIMUM_DATA_RATE_UP_LOW_POWER: u8 = 0x89;
const MINIMUM_DATA_RATE_DOWN_LOW_POWER: u8 = 0x8A;
const MAXIMUM_INTERLEAVING_DELAY_UP: u8 = 0x8B;
const ACTUAL_INTERLEAVING_DELAY_UP: u8 = 0x8C;
const MAXIMUM_INTERLEAVING_DELAY_DOWN: u8 = 0x8D;
const ACTUAL_INTERLEAVING_DELAY_DOWN: u8 = 0x8E;

// TODO: TAG TLVs - defined in rfc 6320 (ANCP)

// vendorid + 16 fields * 4 bytes each + circuit_id + remote_id + 2 byte overhead for each field
const BUFFER_MIN_SIZE: usize = 104;

// TODO: some fancy functions for this
#[derive(Default)]
pub struct AccessLoopEncapsulation {
    data_link: u8,
    encaps1: u8,
    encaps2: u8,
}

macro_rules! write_tlv {
    ($type:expr, $name:expr, $buffer:ident) => {{
        $buffer[0] = $type;
        $buffer[1] = 4;
        NE::write_u32(&mut $buffer[2..], $name);
        $buffer = &mut $buffer[6..];
    }};
}

pub struct Tr101Information {
    circuit_id: (u8, [u8; 64]),
    remote_id: (u8, [u8; 64]),
    pub act_data_rate_up: u32,
    pub act_data_rate_down: u32,
    pub min_data_rate_up: u32,
    pub min_data_rate_down: u32,
    pub att_data_rate_up: u32,
    pub att_data_rate_down: u32,
    pub max_data_rate_up: u32,
    pub max_data_rate_down: u32,
    pub min_data_rate_up_lp: u32,
    pub min_data_rate_down_lp: u32,
    pub max_interl_delay_up: u32,
    pub act_interl_delay_up: u32,
    pub max_interl_delay_down: u32,
    pub act_interl_delay_down: u32,
    pub dsl_type: u32,
    pub access_loop_encapsulation: AccessLoopEncapsulation,
}

impl Tr101Information {
    pub fn with_circuit_id(circuit_id: &str) -> Result<Self, ParseError> {
        Self::with_both_ids(circuit_id, "")
    }

    pub fn with_remote_id(remote_id: &str) -> Result<Self, ParseError> {
        Self::with_both_ids("", remote_id)
    }

    pub fn with_both_ids(circuit_id: &str, remote_id: &str) -> Result<Self, ParseError> {
        let mut tr101: Tr101Information = Default::default();
        tr101.set_remote_id(remote_id)?;
        tr101.set_circuit_id(circuit_id)?;
        Ok(tr101)
    }

    pub fn remote_id(&self) -> &str {
        let len = usize::from(self.remote_id.0);
        unsafe { str::from_utf8_unchecked(&self.remote_id.1[len..]) }
    }

    pub fn circuit_id(&self) -> &str {
        let len = usize::from(self.circuit_id.0);
        unsafe { str::from_utf8_unchecked(&self.circuit_id.1[len..]) }
    }

    pub fn set_remote_id(&mut self, remote_id: &str) -> Result<(), ParseError> {
        let len = remote_id.len();
        if len > 63 {
            return Err(ParseError::InvalidTr101TagLength {
                tag_type: AGENT_REMOTE_ID,
                expected_min_length: 1,
                expected_max_length: 63,
                actual_length: u16::try_from(len).unwrap_or(u16::MAX),
            });
        };
        self.remote_id.1[..len].copy_from_slice(remote_id.as_bytes());
        self.remote_id.0 = len as u8;
        Ok(())
    }

    pub fn set_circuit_id(&mut self, circuit_id: &str) -> Result<(), ParseError> {
        let len = circuit_id.len();
        if len > 63 {
            return Err(ParseError::InvalidTr101TagLength {
                tag_type: AGENT_CIRCUIT_ID,
                expected_min_length: 1,
                expected_max_length: 63,
                actual_length: u16::try_from(len).unwrap_or(u16::MAX),
            });
        }
        self.circuit_id.1[..len].copy_from_slice(circuit_id.as_bytes());
        self.circuit_id.0 = len as u8;
        Ok(())
    }

    pub fn len(&self) -> usize {
        BUFFER_MIN_SIZE + usize::from(self.circuit_id.0) + usize::from(self.remote_id.0)
    }

    #[allow(unused_assignments)]
    pub fn write(&self, mut buffer: &mut [u8]) -> Result<usize, ParseError> {
        let cid_len = usize::from(self.circuit_id.0);
        let rid_len = usize::from(self.remote_id.0);
        let required_size = self.len();
        if buffer.len() < required_size {
            // TODO: better error
            return Err(ParseError::BufferTooSmall(required_size));
        }

        NE::write_u32(&mut buffer, BROADBAND_FORUM_VENDOR_ID);
        buffer = &mut buffer[4..];

        if cid_len != 0 {
            buffer[0] = AGENT_CIRCUIT_ID;
            buffer[1] = cid_len as u8;
            buffer[2..2 + cid_len].copy_from_slice(&self.circuit_id.1[..cid_len]);
            buffer = &mut buffer[2 + cid_len..];
        }

        if rid_len != 0 {
            buffer[0] = AGENT_REMOTE_ID;
            buffer[1] = rid_len as u8;
            buffer[2..2 + rid_len].copy_from_slice(&self.remote_id.1[..rid_len]);
            buffer = &mut buffer[2 + rid_len..];
        }

        buffer[0] = 0x90;
        buffer[1] = 3;
        buffer[2] = self.access_loop_encapsulation.data_link;
        buffer[3] = self.access_loop_encapsulation.encaps1;
        buffer[4] = self.access_loop_encapsulation.encaps2;
        buffer = &mut buffer[5..];

        write_tlv!(ACTUAL_DATA_RATE_UP, self.act_data_rate_up, buffer);
        write_tlv!(ACTUAL_DATA_RATE_DOWN, self.act_data_rate_down, buffer);
        write_tlv!(MINIMUM_DATA_RATE_UP, self.min_data_rate_up, buffer);
        write_tlv!(MINIMUM_DATA_RATE_DOWN, self.min_data_rate_down, buffer);
        write_tlv!(ATTAINABLE_DATA_RATE_UP, self.att_data_rate_up, buffer);
        write_tlv!(ATTAINABLE_DATA_RATE_DOWN, self.att_data_rate_down, buffer);
        write_tlv!(MAXIMUM_DATA_RATE_UP, self.max_data_rate_up, buffer);
        write_tlv!(MAXIMUM_DATA_RATE_DOWN, self.max_data_rate_down, buffer);
        write_tlv!(
            MINIMUM_DATA_RATE_UP_LOW_POWER,
            self.min_data_rate_up_lp,
            buffer
        );
        write_tlv!(
            MINIMUM_DATA_RATE_DOWN_LOW_POWER,
            self.min_data_rate_down_lp,
            buffer
        );
        write_tlv!(
            MAXIMUM_INTERLEAVING_DELAY_UP,
            self.max_interl_delay_up,
            buffer
        );
        write_tlv!(
            ACTUAL_INTERLEAVING_DELAY_UP,
            self.act_interl_delay_up,
            buffer
        );
        write_tlv!(
            MAXIMUM_INTERLEAVING_DELAY_DOWN,
            self.max_interl_delay_down,
            buffer
        );
        write_tlv!(
            ACTUAL_INTERLEAVING_DELAY_DOWN,
            self.act_interl_delay_down,
            buffer
        );

        Ok(required_size)
    }
}

impl Default for Tr101Information {
    fn default() -> Self {
        Self {
            circuit_id: (0, [0; 64]),
            remote_id: (0, [0; 64]),
            act_data_rate_up: 0,
            act_data_rate_down: 0,
            min_data_rate_up: 0,
            min_data_rate_down: 0,
            att_data_rate_up: 0,
            att_data_rate_down: 0,
            max_data_rate_up: 0,
            max_data_rate_down: 0,
            min_data_rate_up_lp: 0,
            min_data_rate_down_lp: 0,
            max_interl_delay_up: 0,
            act_interl_delay_up: 0,
            max_interl_delay_down: 0,
            act_interl_delay_down: 0,
            access_loop_encapsulation: Default::default(),
            dsl_type: 0,
        }
    }
}

impl<'a> TryFrom<TagIterator<'a>> for Tr101Information {
    type Error = ();

    fn try_from(tag_iterator: TagIterator<'a>) -> Result<Tr101Information, Self::Error> {
        for tag in tag_iterator {
            match Self::try_from(tag) {
                Ok(info) => {
                    return Ok(info);
                }
                _ => (),
            }
        }
        Err(())
    }
}

impl<'a> TryFrom<Tag<'a>> for Tr101Information {
    type Error = ParseError;

    fn try_from(tag: Tag) -> Result<Tr101Information, Self::Error> {
        if let Tag::VendorSpecific(buffer) = tag {
            if buffer.len() < 4 {
                return Err(ParseError::IncompleteTag(buffer.len() as u8));
            }

            let vendor_id = NE::read_u32(buffer);
            if vendor_id != BROADBAND_FORUM_VENDOR_ID {
                return Err(ParseError::InvalidTr101VendorId(vendor_id));
            }
            let mut info = Tr101Information::default();
            let tr_iter = Tr101TagIterator { buffer };

            for tr_tag in tr_iter {
                let tr_tag = tr_tag?;
                match tr_tag {
                    Tr101Tag::CircuitId(cid) => {
                        info.circuit_id.0 = cid.len() as u8;
                        info.circuit_id.1[..cid.len()].copy_from_slice(cid);
                    }
                    Tr101Tag::RemoteId(rid) => {
                        info.remote_id.0 = rid.len() as u8;
                        info.remote_id.1[..rid.len()].copy_from_slice(rid);
                    }
                    Tr101Tag::ActDataRateUp(rate) => {
                        info.act_data_rate_up = rate;
                    }
                    Tr101Tag::ActDataRateDown(rate) => {
                        info.act_data_rate_down = rate;
                    }
                    Tr101Tag::MinDataRateUp(rate) => {
                        info.min_data_rate_up = rate;
                    }
                    Tr101Tag::MinDataRateDown(rate) => {
                        info.min_data_rate_down = rate;
                    }
                    Tr101Tag::AttDataRateUp(rate) => {
                        info.att_data_rate_up = rate;
                    }
                    Tr101Tag::AttDataRateDown(rate) => {
                        info.att_data_rate_down = rate;
                    }
                    Tr101Tag::MaxDataRateUp(rate) => {
                        info.max_data_rate_up = rate;
                    }
                    Tr101Tag::MaxDataRateDown(rate) => {
                        info.max_data_rate_down = rate;
                    }
                    Tr101Tag::MinDataRateUpLp(rate) => {
                        info.min_data_rate_up_lp = rate;
                    }
                    Tr101Tag::MinDataRateDownLp(rate) => {
                        info.min_data_rate_down_lp = rate;
                    }
                    Tr101Tag::MaxInterlDelayUp(rate) => {
                        info.max_interl_delay_up = rate;
                    }
                    Tr101Tag::ActInterlDelayUp(rate) => {
                        info.act_interl_delay_down = rate;
                    }
                    Tr101Tag::MaxInterlDelayDown(rate) => {
                        info.max_interl_delay_up = rate;
                    }
                    Tr101Tag::ActInterlDelayDown(rate) => {
                        info.act_interl_delay_down = rate;
                    }
                    Tr101Tag::DslType(dsl_type) => {
                        info.dsl_type = dsl_type;
                    }
                    Tr101Tag::AccessLoopEncapsulation(ale) => info.access_loop_encapsulation = ale,
                    Tr101Tag::Unknown(_) => (),
                }
            }

            return Ok(info);
        }
        Err(ParseError::TagIsNotVendorSpecific)
    }
}

pub enum Tr101Tag<'a> {
    CircuitId(&'a [u8]),
    RemoteId(&'a [u8]),
    ActDataRateUp(u32),
    ActDataRateDown(u32),
    MinDataRateUp(u32),
    MinDataRateDown(u32),
    AttDataRateUp(u32),
    AttDataRateDown(u32),
    MaxDataRateUp(u32),
    MaxDataRateDown(u32),
    MinDataRateUpLp(u32),
    MinDataRateDownLp(u32),
    MaxInterlDelayUp(u32),
    ActInterlDelayUp(u32),
    MaxInterlDelayDown(u32),
    ActInterlDelayDown(u32),
    DslType(u32),
    AccessLoopEncapsulation(AccessLoopEncapsulation),
    Unknown((u8, &'a [u8])),
}

pub struct Tr101TagIterator<'a> {
    buffer: &'a [u8],
}

macro_rules! read_tag {
    ($type:expr, $tag:path, $buffer:expr, $length:expr) => {{
        if $length != 6 {
            return Some(Err(ParseError::InvalidTr101TagLength {
                tag_type: $type,
                expected_min_length: 6,
                expected_max_length: 6,
                actual_length: $length as u16,
            }));
        }

        $tag(NE::read_u32(&$buffer[2..]))
    }};
}

impl<'a> Iterator for Tr101TagIterator<'a> {
    type Item = Result<Tr101Tag<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() == 0 {
            return None;
        }

        let tag_type = self.buffer[0];
        let tag_length = usize::from(self.buffer[1]) + 2;

        if tag_length > self.buffer.len() {
            self.buffer = &[];
            return Some(Err(ParseError::Tr101LengthOutOfBound {
                remaining_packet_length: self.buffer.len() as u16,
                requested_tag_length: tag_length as u16,
            }));
        }

        let tag = match tag_type {
            AGENT_CIRCUIT_ID => {
                if tag_length > 65 {
                    return Some(Err(ParseError::InvalidTr101TagLength {
                        tag_type: AGENT_CIRCUIT_ID,
                        expected_min_length: 1,
                        expected_max_length: 63,
                        actual_length: tag_length as u16,
                    }));
                }
                Tr101Tag::CircuitId(&self.buffer[2..tag_length])
            }
            AGENT_REMOTE_ID => {
                if tag_length > 65 {
                    return Some(Err(ParseError::InvalidTr101TagLength {
                        tag_type: AGENT_REMOTE_ID,
                        expected_min_length: 1,
                        expected_max_length: 63,
                        actual_length: tag_length as u16,
                    }));
                }
                Tr101Tag::RemoteId(&self.buffer[2..tag_length])
            }
            ACTUAL_DATA_RATE_UP => read_tag!(
                ACTUAL_DATA_RATE_UP,
                Tr101Tag::ActDataRateUp,
                self.buffer,
                tag_length
            ),
            ACTUAL_DATA_RATE_DOWN => read_tag!(
                ACTUAL_DATA_RATE_DOWN,
                Tr101Tag::ActDataRateDown,
                self.buffer,
                tag_length
            ),
            MINIMUM_DATA_RATE_UP => read_tag!(
                MINIMUM_DATA_RATE_UP,
                Tr101Tag::MinDataRateUp,
                self.buffer,
                tag_length
            ),
            MINIMUM_DATA_RATE_DOWN => read_tag!(
                MINIMUM_DATA_RATE_DOWN,
                Tr101Tag::MinDataRateDown,
                self.buffer,
                tag_length
            ),
            ATTAINABLE_DATA_RATE_UP => read_tag!(
                ATTAINABLE_DATA_RATE_UP,
                Tr101Tag::AttDataRateUp,
                self.buffer,
                tag_length
            ),
            ATTAINABLE_DATA_RATE_DOWN => read_tag!(
                ATTAINABLE_DATA_RATE_DOWN,
                Tr101Tag::AttDataRateDown,
                self.buffer,
                tag_length
            ),
            MAXIMUM_DATA_RATE_UP => read_tag!(
                MAXIMUM_DATA_RATE_UP,
                Tr101Tag::MaxDataRateUp,
                self.buffer,
                tag_length
            ),
            MAXIMUM_DATA_RATE_DOWN => read_tag!(
                MAXIMUM_DATA_RATE_DOWN,
                Tr101Tag::MaxDataRateDown,
                self.buffer,
                tag_length
            ),
            MINIMUM_DATA_RATE_UP_LOW_POWER => read_tag!(
                MINIMUM_DATA_RATE_UP_LOW_POWER,
                Tr101Tag::MinDataRateUp,
                self.buffer,
                tag_length
            ),
            MINIMUM_DATA_RATE_DOWN_LOW_POWER => read_tag!(
                MINIMUM_DATA_RATE_DOWN_LOW_POWER,
                Tr101Tag::MinDataRateDown,
                self.buffer,
                tag_length
            ),
            MAXIMUM_INTERLEAVING_DELAY_UP => read_tag!(
                MAXIMUM_INTERLEAVING_DELAY_UP,
                Tr101Tag::MaxDataRateUp,
                self.buffer,
                tag_length
            ),
            ACTUAL_INTERLEAVING_DELAY_UP => read_tag!(
                ACTUAL_INTERLEAVING_DELAY_UP,
                Tr101Tag::ActDataRateDown,
                self.buffer,
                tag_length
            ),
            MAXIMUM_INTERLEAVING_DELAY_DOWN => read_tag!(
                MAXIMUM_INTERLEAVING_DELAY_DOWN,
                Tr101Tag::MaxDataRateUp,
                self.buffer,
                tag_length
            ),
            ACTUAL_INTERLEAVING_DELAY_DOWN => read_tag!(
                ACTUAL_INTERLEAVING_DELAY_DOWN,
                Tr101Tag::ActDataRateDown,
                self.buffer,
                tag_length
            ),
            unknown => Tr101Tag::Unknown((unknown, &self.buffer[2..tag_length])),
        };

        self.buffer = &self.buffer[tag_length..];

        Some(Ok(tag))
    }
}

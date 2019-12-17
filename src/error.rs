use std::io;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ParseError {
    BufferTooSmall(usize),

    BufferTooSmallForTag {
        available: u16,
        requested: usize,
    },

    InvalidPppoeVersion(u8),
    InvalidPppoeType(u8),
    InvalidPppoeCode(u8),

    UnexpectedCode(u8),

    PayloadLengthOutOfBound {
        actual_packet_length: u16,
        payload_length: u16,
    },
    TagLengthOutOfBound {
        expected_tag_length: u16,
        remaining_payload_length: u16,
    },

    IncompleteTagAtPacketEnd {
        total_packet_length: u16,
        left_over_bytes: u16,
    },

    DataBehindEolTag,
    IncompleteTag(u8),
    TagWithInvalidLength {
        tag_type: u16,
        length: u16,
    },

    #[cfg(feature = "tr101")]
    InvalidTr101TagLength {
        tag_type: u8,
        expected_min_length: u16,
        expected_max_length: u16,
        actual_length: u16,
    },
    #[cfg(feature = "tr101")]
    Tr101LengthOutOfBound {
        remaining_packet_length: u16,
        requested_tag_length: u16,
    },
    #[cfg(feature = "tr101")]
    InvalidTr101Id(u32),
    #[cfg(feature = "tr101")]
    TagIsNotVendorSpecific,
    #[cfg(feature = "tr101")]
    InvalidTr101VendorId(u32),

    DuplicateTag(u16),

    MissingServiceName,
    MissingAcName,

    ServiceNameMismatch,
    AcNameMismatch,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ParseError(ParseError),
    TODO,
}

impl From<ParseError> for Error {
    fn from(error: ParseError) -> Self {
        Error::ParseError(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Error::TODO
    }
}

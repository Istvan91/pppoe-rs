#[cfg(feature = "socket")]
pub mod socket;
#[cfg(feature = "socket")]
pub use socket::Socket;

pub mod header;
pub use header::{Code, Header, HeaderBuilder};

pub mod packet;
pub use packet::{Packet, PacketBuilder};

pub mod error;
pub mod eth;

mod tags;
#[cfg(features = "tr101")]
pub use tag::Tr101Information;
pub use tags::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "tr101")]
    #[test]
    fn send_packet() {
        let sock = Socket::on_interface("pppoe");
        assert!(sock.is_ok());
        let sock = sock.unwrap();

        let mut receive_buffer = [0u8; 1450];
        let mut buffer = [0u8; 1450];
        let mut packet = PacketBuilder::new_discovery_packet(
            &mut buffer[..],
            [0xfe, 0xb9, 0x04, 0x2a, 0xb2, 0x35],
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        )
        .unwrap();

        {
            let pppoe_header = packet.pppoe_header();
            pppoe_header.add_tag(Tag::PppMaxMtu(2000)).unwrap();
            pppoe_header.add_tag(Tag::ServiceName(b"\0")).unwrap();
            pppoe_header.add_tag(Tag::RelaySessionId(b"abc")).unwrap();
            pppoe_header
                .add_tag(Tag::HostUniq(b"abcanretadi\0arnedt"))
                .unwrap();
            pppoe_header
                .add_vendor_tag_with_callback(|buffer| {
                    Tr101Information::with_both_ids("circuit", "remoteid")
                        .and_then(|tr101| tr101.write(buffer))
                })
                .unwrap();
            pppoe_header.add_tag(Tag::EndOfList).unwrap();
        }

        let ret = sock.send(packet.as_bytes());
        assert!(ret.is_ok());

        let len = sock.recv(&mut receive_buffer[..]).unwrap();
        let pado = Packet::with_buffer(&mut receive_buffer[..len]).unwrap();

        {
            let dst = pado.ethernet_header().src_address();
            packet.ethernet_header().set_dst_address(dst);
            let pppoe_header = packet.pppoe_header();
            pppoe_header.set_code(Code::Padr);
            pppoe_header.clear_eol();

            for tag in pado.pppoe_header().tags() {
                if let Tag::AcCookie(cookie) = tag {
                    pppoe_header.add_tag(Tag::AcCookie(cookie)).unwrap();
                }
            }

            pppoe_header.add_tag(Tag::EndOfList).unwrap();
        }

        let ret = sock.send(packet.as_bytes());
        assert!(ret.is_ok());

        let _len = sock.recv(&mut receive_buffer[..]).unwrap();
    }
}

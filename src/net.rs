use log::trace;

#[derive(Debug, PartialEq)]
pub enum IpProtocol {
    Unsupported,
    Icmp, // 0x1
    Udp   // 0x11
}

/// This struct is used for reintepreting a byte array `[u8]` as an IP packet.
/// See [RFC 791](https://datatracker.ietf.org/doc/html/rfc791)
pub struct IpPacket<'a> {
    data: &'a [u8]
}

impl<'a> std::fmt::Debug for IpPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "(IPv4) version: {}, ihl: {}, dscp: {}, ecn: {}, \
            total_length: {}, identification: {}, flags: {}, fragment_offset: {}, \
            ttl: {}, protocol: {:?}, header_checksum: {}, src_addr: {:?}, dst_addr: {:?}, \
            payload: ({} bytes)", 
            self.version(), self.ihl(), self.dscp(), self.ecn(),
            self.total_length(), self.identification(), self.flags(), self.fragment_offset(),
            self.ttl(), self.protocol(), self.header_checksum(), self.src_addr(), self.dst_addr(),
            self.payload().len()
        )
    }
}

impl<'a> std::fmt::Display for IpPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_as_hex(&self.data))
    }
}

impl<'a> IpPacket<'a> {
    pub fn new(data: &'a [u8]) -> IpPacket {
        IpPacket{data}
    }
    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }
    pub fn ihl(&self) -> u8 {
        self.data[0] & 15
    }
    pub fn dscp(&self) -> u8 {
        self.data[1] >> 2
    }
    pub fn ecn(&self) -> u8 {
        self.data[1] & 3
    }
    pub fn total_length(&self) -> u16 {
        (self.data[3] as u16) + ((self.data[2] as u16) << 8)
    }
    pub fn identification(&self) -> u16 {
        (self.data[5] as u16) + ((self.data[4] as u16) << 8)
    }
    pub fn flags(&self) -> u8 {
        self.data[6] >> 5
    }
    pub fn fragment_offset(&self) -> u16 {
        (self.data[7] as u16) + (((self.data[6] & 31) as u16) << 8)
    }
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }
    pub fn protocol(&self) -> IpProtocol {
        match self.data[9] {
            0x1 => IpProtocol::Icmp,
            0x11 => IpProtocol::Udp,
            _ => { 
                trace!("Only ICMP and UDP protocol supported");
                IpProtocol::Unsupported
            }
        }
    }
    pub fn header_checksum(&self) -> u16 {
        (self.data[11] as u16) + ((self.data[10] as u16) << 8)
    }
    pub fn src_addr(&self) -> std::net::IpAddr {
        // TODO: handle IPv6
        std::net::IpAddr::V4(std::net::Ipv4Addr::from([self.data[12], self.data[13], self.data[14], self.data[15]]))
    }
    pub fn dst_addr(&self) -> std::net::IpAddr {
        // TODO: handle IPv6
        std::net::IpAddr::V4(std::net::Ipv4Addr::from([self.data[16], self.data[17], self.data[18], self.data[19]]))
    }
    pub fn payload(&self) -> &[u8] {
        &self.data[20..]
    }
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum IcmpType {
    EchoReply = 0,
    EchoRequest = 8,
    TimeExceeded = 11,
}

/// This struct is used for reintepreting a byte array `[u8]` as an ICMP packet.
/// See [RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
pub struct IcmpPacket<'a> {
    data: &'a [u8],
}

impl<'a> std::fmt::Debug for IcmpPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let icmp_type = match self.typ() {
            Ok(typ) => typ as u8,
            Err(typ) => typ,
        };
        write!(f, "(ICMP) type: {}, code: {}, checksum: {}, \
            rest_of_header: {: >3} {: >3} {: >3} {: >3}, \
            payload: ({} bytes)", 
            icmp_type as u8, self.code(), self.checksum(), 
            self.rest_of_header()[0], self.rest_of_header()[1], self.rest_of_header()[2], self.rest_of_header()[3],
            self.payload().len()
        )
    }
}

impl<'a> std::fmt::Display for IcmpPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_as_hex(&self.data))
    }
}

impl<'a> IcmpPacket<'a> {
    pub fn new(data: &'a [u8]) -> IcmpPacket {
        IcmpPacket{data}
    }
    pub fn typ(&self) -> Result<IcmpType, u8> {
        match self.data[0] {
            0 => Ok(IcmpType::EchoReply),
            8 => Ok(IcmpType::EchoRequest),
            11 => Ok(IcmpType::TimeExceeded),
            other => {
                trace!("Unsupported value for ICMP type: {}", other);
                Err(self.data[0])
            }
        }
    }
    pub fn code(&self) -> u8 {
        self.data[1]
    }
    pub fn checksum(&self) -> u16 {
        (self.data[3] as u16) + ((self.data[2] as u16) << 8)
    }
    pub fn rest_of_header(&self) -> &[u8; 4] {
        self.data[4..8].try_into().unwrap()
    }
    pub fn payload(&self) -> &[u8] {
        &self.data[8..]
    }
}

pub struct IcmpPacketBuilder {
    icmp_data: Vec<u8>
}
impl IcmpPacketBuilder {
    pub fn new() -> IcmpPacketBuilder {
        IcmpPacketBuilder{
            icmp_data: vec![0; 8], // icmp header is 8 bytes
        }
    }
    pub fn with_type(&mut self, typ: &IcmpType) -> &mut IcmpPacketBuilder {
        self.icmp_data[0] = *typ as u8;
        self
    }
    pub fn with_payload(&mut self, payload: &mut Vec<u8>)-> &mut IcmpPacketBuilder {
        // TODO: check if not too long
        self.icmp_data.resize(8, 0);
        self.icmp_data.append(payload);
        self
    }
    pub fn build(&mut self) -> Vec<u8> {
        let checksum = calculate_checksum(&self.icmp_data);
        self.icmp_data[2] = (checksum >> 8) as u8;
        self.icmp_data[3] = (checksum & 0xff) as u8;
        self.icmp_data.clone()
    }

}

/// Format an array of bytes as hex characters
fn format_as_hex(a: &[u8]) -> String {
    a.into_iter()
    .map(|x| format!("{:0>2X}", x))
    .collect::<Vec<String>>()
    .join(" ")
}

/// Calculates the IPv4 checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in data.chunks(2) {
        sum += (word[0] as u32) << 8;
        if word.len() > 1 {
            sum += word[1] as u32;
        }
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let sum = !sum as u16;
    if sum == 0 {
        0xffff
    } else {
        sum
    }
}

//
//
//

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_calculate_checksum_of_udp_pseudo_header() {
        // from: 10.8.0.83 -- to: 8.8.8.8
        // (UDP) src_port: 8080, dst_port: 39812, length: 8, checksum: 10847,
        // src    dst       len    csum   'h' 'a' 'l' 'l' 'o' ' ' '4' '\n'
        // 31 144 155 132   0   8  42  95
        let expected_checksum = 10847;
        
        {
            // Receiving side will make this check.
            // The `pseudo_header` with the checksum filled it should sum up to 0xffff.
            let pseudo_header = [
                8,8,8,8, // destination ip
                10, 8, 0, 83, // source ip
                0, // zeroes
                0x11, // IP protocol 0x11 for UDP
                0, 8, // UDP length 
                31, 144, // src port
                155, 132, // dst port
                0,  8, // UDP length
                42,   95, // checksum
                 // payload is empty
                ];
            let mut sum = 0u32;
            for x in pseudo_header.chunks(2) {
                let part = ((x[0] as u32) << 8) + (x[1] as u32);
                sum += part;
            }
            assert_eq!(0xffff, sum);
        }

        {
            // While calculating the checksum of the `pseudo_header` of a udp packet, the two checksum bytes are set to zero.
            let pseudo_header = [
                8,8,8,8, // destination ip
                10, 8, 0, 83, // source ip
                0, // zeroes
                0x11, // IP protocol 0x11 for UDP
                0, 8, // UDP length 
                31, 144, // src port
                155, 132, // dst port
                0,  8, // UDP length
                0,   0, // checksum zeros
                 // payload is empty
                ];
                println!("{}", format_as_hex(&pseudo_header));
                let checksum = calculate_checksum(&pseudo_header);
                assert_eq!(expected_checksum, checksum);
        }

    }
}
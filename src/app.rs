use crate::socket_wrapper;
use crate::net;

use std::net::IpAddr;

use log::trace;

enum InboundPacketError {
    SilentDrop,
}

/// The `Engine` takes a target (or destiantion) IP address and generates a list of routers that
/// sit in between the client and the target machine. 
pub struct Engine {
    dst_ip: std::net::IpAddr,
    max_ttl: u8,
    timeout_duration: tokio::time::Duration,

    // These callbacks could be exposed to modify behaviour of the `Engine` struct.
    // Called to grab a new port number of sending ICMP packets
    dst_port_provider: fn() -> u16, 
    // Called to signal that a hop was successfully made.
    on_hop: fn() -> (),
    // Called to signal that the target IP address was reached. End of the program.
    on_destination_reached: fn() -> (),

    inet_domain: socket2::Domain,
}

impl Engine {

    pub async fn new(dst_ip: std::net::IpAddr, max_ttl: u8, timeout_duration: tokio::time::Duration) -> Engine {
        Engine{
            dst_ip,
            max_ttl,
            timeout_duration,
            dst_port_provider: rand::random::<u16>,
            on_hop: || (),
            on_destination_reached: || (),
            inet_domain: match dst_ip {
                std::net::IpAddr::V4(_) => {
                    socket2::Domain::IPV4
                },
                std::net::IpAddr::V6(_) => {
                    socket2::Domain::IPV6
                },
            },
        }
    }

    /// An incoming packet is silently dropped if:
    ///  - ihl > 5
    ///  - IP protocol is not ICMP
    /// An incoming packet is marked as handled correctly only if:
    ///  - ICMP type is EchoReply and source address is our target IP address
    ///  - ICMP type is TTL exceeded and the inner packet has the checksum of our latest outbound packet.
    /// Returns true if the packet was handled correctly, else false.
    fn handle_inbound_packet(&self, bytes: &[u8], expected_checksum: u16) -> Result<IpAddr, InboundPacketError> {
        let ip_packet = net::IpPacket::new(&bytes);
        if ip_packet.ihl() > 5 {
            // silently reject packets with ihl > 5
            trace!("Silently dropping packet: ihl > 5 [{:?}]", ip_packet);
            return Err(InboundPacketError::SilentDrop);
        }
        if ip_packet.protocol() != net::IpProtocol::Icmp {
            // silently reject packets that are not ICMP
            trace!("Silently dropping packet: protocol not ICMP [{:?}]", ip_packet);
            return Err(InboundPacketError::SilentDrop);
        }

        let icmp_packet = net::IcmpPacket::new(ip_packet.payload());
        match icmp_packet.typ() {
            Ok(typ) => {
                match typ {
                    net::IcmpType::EchoReply => {
                        if ip_packet.src_addr() == self.dst_ip {
                            // finished with trace routing
                            trace!("Received echo reply from target ip: {}", ip_packet.src_addr());
                            Ok(ip_packet.src_addr())
                        } else {
                            // silently reject echo reply that does not come from our target ip
                            trace!("Silently dropping echo reply from unknown ip: {}", ip_packet.src_addr());
                            Err(InboundPacketError::SilentDrop)
                        }
                    },
                    net::IcmpType::TimeExceeded => {
                        let ip_packet2 = net::IpPacket::new(icmp_packet.payload());
                        let checksum = net::IcmpPacket::new(ip_packet2.payload()).checksum();
                        if checksum == expected_checksum {
                            // packet accepted
                            trace!("Received time to live exceeded from {} (checksum {})", ip_packet.src_addr(), checksum);
                            Ok(ip_packet.src_addr())
                        } else {
                            // silently reject packets with incorret checksum
                            // They might have been valid for previous probes but those timed out.
                            trace!("Silently dropping time to live exceeded from {} with unknow checksum {}", ip_packet.src_addr(), checksum);
                            Err(InboundPacketError::SilentDrop)
                        }
                    },
                    net::IcmpType::EchoRequest => {
                        // silently reject echo requests
                        trace!("Silently dropping echo request from: {}", ip_packet.src_addr());
                        Err(InboundPacketError::SilentDrop)
                    }
                }
            },
            Err(_) => {
                // silently reject packets if ICMP type is not supported by our net layer
                trace!("Silently dropping non ICMP packet from: {}", ip_packet.src_addr());
                Err(InboundPacketError::SilentDrop)
            }
        }
    }

    /// Send an ICMP EchoRequest packet to the target ip address.
    /// Returns checksum of the ICMP header and a timestamp of sending the packet.
    async fn send_icmp(&self, ttl: u8, socket_send: &socket_wrapper::RawSocketTokio) -> (u16, tokio::time::Instant) {
        let mut builder = net::IcmpPacketBuilder::new();
        builder
            .with_type(&net::IcmpType::EchoRequest)
            .with_payload(&mut vec![rand::random::<u8>()]);
        let bytes_to_send: Vec<u8> = builder.build();
        let checksum = net::IcmpPacket::new(&bytes_to_send).checksum();

        let port = (self.dst_port_provider)();
        let addr = std::net::SocketAddr::new(self.dst_ip, port);
        socket_send.set_ttl(ttl).expect("Failed to set ttl on outbound socket");
        socket_send.send_to(&bytes_to_send, addr.into()).await
            .expect(format!("Failed to send packet to {}:{}", addr, port).as_str());
        trace!("Sent ICMP packet with ttl {} to {} (checksum {})", ttl, addr, checksum);
        (checksum, tokio::time::Instant::now())
    }

    /// Creates an outbound socket and an inbound socket.
    /// On the outbound socket an ICMP EchoRequest is sent to the target ip address. 
    /// The inbound socket will wait for two types of incoming messages: TTL exceeded and EchoReply.
    /// All other traffic on the inbound socket is silently dropped.
    /// The time-to-live is incremented from 1 until the the target ip sends us an EchoReply message.
    pub async fn run(&mut self) {
        let inet_domain = self.inet_domain;
        let socket_send = socket_wrapper::RawSocketTokio::new(inet_domain, socket2::Protocol::ICMPV4)
        .expect("Failed to create outbound socket");
        let socket_recv = socket_wrapper::RawSocketTokio::new(inet_domain, socket2::Protocol::ICMPV4)
        .expect("Failed to create inbound socket");
        let mut buf_in = [0 as u8; 1024];

        let mut ttl = 1u8;

        let (mut expected_checksum, mut outbound_timestamp) = self.send_icmp(ttl, &socket_send).await;
        loop {
            tokio::select! {
                nbytes_or_timeout = tokio::time::timeout(
                    self.timeout_duration, 
                    socket_recv.recv(&mut buf_in)
                ) => {
                    match nbytes_or_timeout {
                        Ok(Ok(nbytes)) => {
                            let inbound_timestamp = tokio::time::Instant::now();
                            // not timed out and no socket error
                            match self.handle_inbound_packet(&buf_in[..nbytes], expected_checksum) {
                                Ok(src_ip) => {
                                    if src_ip == self.dst_ip {
                                        // done tracing
                                        self.report_dst_reached(ttl, inbound_timestamp - outbound_timestamp);
                                        (self.on_destination_reached)();
                                        break;
                                    } else {
                                        self.report_hop(ttl, src_ip, inbound_timestamp - outbound_timestamp);
                                        (self.on_hop)();
                                        ttl += 1;
                                        if ttl > self.max_ttl {
                                            break;
                                        }
                                        (expected_checksum, outbound_timestamp) = self.send_icmp(ttl, &socket_send).await;
                                    }
                                },
                                Err(InboundPacketError::SilentDrop) => {
                                    // pass
                                }
                            };
                        },
                        Ok(Err(_)) => {
                            // socket error
                            
                        },
                        Err(_) => {
                            // timed out, move on to the next 
                                self.report_hop_timeout(ttl);
                            ttl += 1;
                            if ttl > self.max_ttl {
                                break;
                            }
                            (expected_checksum, outbound_timestamp) = self.send_icmp(ttl, &socket_send).await;
                            
                        }
                    };
                }
            };
        }

    }

    fn report_hop(&self, ttl: u8, dst_ip: IpAddr, latency: tokio::time::Duration) {
        println!("{:3} {:16} ({:4} ms)", ttl, dst_ip, latency.as_millis());
    }
    fn report_hop_timeout(&self, ttl: u8) {
        println!("{:3} * * *", ttl);

    }
    fn report_dst_reached(&self, ttl: u8, latency: tokio::time::Duration) {
        println!("{:3} {:16} ({:4} ms)", ttl, self.dst_ip, latency.as_millis());
    }
}
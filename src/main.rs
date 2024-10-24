use clap::{App, Arg};
use hexdump;
use pcap::{Capture, Device};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use std::net::IpAddr;

fn main() {
    // Parse command-line arguments
    let matches = App::new("Packet Filter")
        .version("1.0")
        .author("Your Name")
        .about("Filters packets based on criteria and performs a hexdump")
        .arg(
            Arg::new("src_ip")
                .long("src-ip")
                .value_name("SRC_IP")
                .help("Filter packets with source IP")
                .value_parser(clap::value_parser!(IpAddr)),
        )
        .arg(
            Arg::new("dst_ip")
                .long("dst-ip")
                .value_name("DST_IP")
                .help("Filter packets with destination IP")
                .value_parser(clap::value_parser!(IpAddr)),
        )
        .arg(
            Arg::new("content")
                .long("content")
                .value_name("CONTENT")
                .help("Filter packets containing specific content"),
        )
        .arg(
            Arg::new("tcp_flags")
                .long("tcp-flags")
                .value_name("FLAGS")
                .help("Filter packets with specific TCP flags (e.g., SYN,ACK)"),
        )
        .arg(
            Arg::new("src_port")
                .long("src-port")
                .value_name("SRC_PORT")
                .help("Filter packets with source port")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("dst_port")
                .long("dst-port")
                .value_name("DST_PORT")
                .help("Filter packets with destination port")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .help("Filter packets with source or destination port")
                .value_parser(clap::value_parser!(u16)),
        )
        .get_matches();

    let src_ip = matches.get_one::<IpAddr>("src_ip");
    let dst_ip = matches.get_one::<IpAddr>("dst_ip");
    let content = matches.get_one::<String>("content").map(String::as_str);
    let tcp_flags = matches.get_one::<String>("tcp_flags").map(String::as_str);
    let src_port = matches.get_one::<u16>("src_port");
    let dst_port = matches.get_one::<u16>("dst_port");
    let port = matches.get_one::<u16>("port");

    // Open the default device
    let mut cap = Device::lookup()
        .expect("Failed to lookup device")
        .open()
        .expect("Failed to open device");

    while let Ok(packet) = cap.next() {
        // Parse Ethernet header
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    // Parse IPv4 header
                    if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                        match ip_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                // Parse TCP header
                                if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                                    // Extract information
                                    let packet_src_ip = IpAddr::V4(ip_packet.get_source());
                                    let packet_dst_ip = IpAddr::V4(ip_packet.get_destination());
                                    let packet_src_port = tcp_packet.get_source();
                                    let packet_dst_port = tcp_packet.get_destination();
                                    let packet_tcp_flags = tcp_packet.get_flags();
                                    let packet_payload = tcp_packet.payload();

                                    let mut matched = true;

                                    // Check source IP
                                    if let Some(filter_src_ip) = src_ip {
                                        if &packet_src_ip != filter_src_ip {
                                            matched = false;
                                        }
                                    }

                                    // Check destination IP
                                    if let Some(filter_dst_ip) = dst_ip {
                                        if &packet_dst_ip != filter_dst_ip {
                                            matched = false;
                                        }
                                    }

                                    // Check source port
                                    if let Some(&filter_src_port) = src_port {
                                        if packet_src_port != filter_src_port {
                                            matched = false;
                                        }
                                    }

                                    // Check destination port
                                    if let Some(&filter_dst_port) = dst_port {
                                        if packet_dst_port != filter_dst_port {
                                            matched = false;
                                        }
                                    }

                                    // Check port (either source or destination)
                                    if let Some(&filter_port) = port {
                                        if packet_src_port != filter_port
                                            && packet_dst_port != filter_port
                                        {
                                            matched = false;
                                        }
                                    }

                                    // Check packet content
                                    if let Some(filter_content) = content {
                                        let content_bytes = filter_content.as_bytes();
                                        if !packet_payload
                                            .windows(content_bytes.len())
                                            .any(|window| window == content_bytes)
                                        {
                                            matched = false;
                                        }
                                    }

                                    // Check TCP flags
                                    if let Some(filter_tcp_flags_str) = tcp_flags {
                                        let filter_tcp_flags =
                                            parse_tcp_flags(filter_tcp_flags_str);
                                        if (packet_tcp_flags & filter_tcp_flags)
                                            != filter_tcp_flags
                                        {
                                            matched = false;
                                        }
                                    }

                                    // Perform hexdump if all criteria matched
                                    if matched {
                                        hexdump::hexdump(packet.data);
                                    }
                                }
                            }
                            _ => {} // Ignore other protocols
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    // Parse IPv6 header
                    if let Some(ip_packet) = Ipv6Packet::new(ethernet.payload()) {
                        match ip_packet.get_next_header() {
                            IpNextHeaderProtocols::Tcp => {
                                // Parse TCP header
                                if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                                    // Extract information
                                    let packet_src_ip = IpAddr::V6(ip_packet.get_source());
                                    let packet_dst_ip = IpAddr::V6(ip_packet.get_destination());
                                    let packet_src_port = tcp_packet.get_source();
                                    let packet_dst_port = tcp_packet.get_destination();
                                    let packet_tcp_flags = tcp_packet.get_flags();
                                    let packet_payload = tcp_packet.payload();

                                    let mut matched = true;

                                    // Check source IP
                                    if let Some(filter_src_ip) = src_ip {
                                        if &packet_src_ip != filter_src_ip {
                                            matched = false;
                                        }
                                    }

                                    // Check destination IP
                                    if let Some(filter_dst_ip) = dst_ip {
                                        if &packet_dst_ip != filter_dst_ip {
                                            matched = false;
                                        }
                                    }

                                    // Check source port
                                    if let Some(&filter_src_port) = src_port {
                                        if packet_src_port != filter_src_port {
                                            matched = false;
                                        }
                                    }

                                    // Check destination port
                                    if let Some(&filter_dst_port) = dst_port {
                                        if packet_dst_port != filter_dst_port {
                                            matched = false;
                                        }
                                    }

                                    // Check port (either source or destination)
                                    if let Some(&filter_port) = port {
                                        if packet_src_port != filter_port
                                            && packet_dst_port != filter_port
                                        {
                                            matched = false;
                                        }
                                    }

                                    // Check packet content
                                    if let Some(filter_content) = content {
                                        let content_bytes = filter_content.as_bytes();
                                        if !packet_payload
                                            .windows(content_bytes.len())
                                            .any(|window| window == content_bytes)
                                        {
                                            matched = false;
                                        }
                                    }

                                    // Check TCP flags
                                    if let Some(filter_tcp_flags_str) = tcp_flags {
                                        let filter_tcp_flags =
                                            parse_tcp_flags(filter_tcp_flags_str);
                                        if (packet_tcp_flags & filter_tcp_flags)
                                            != filter_tcp_flags
                                        {
                                            matched = false;
                                        }
                                    }

                                    // Perform hexdump if all criteria matched
                                    if matched {
                                        hexdump::hexdump(packet.data);
                                    }
                                }
                            }
                            _ => {} // Ignore other protocols
                        }
                    }
                }
                _ => {} // Ignore other EtherTypes
            }
        }
    }
}

// Function to parse TCP flags from a comma-separated string
fn parse_tcp_flags(flags_str: &str) -> u8 {
    let mut flags = 0;
    let flags_list: Vec<&str> = flags_str.split(',').collect();
    for flag in flags_list {
        match flag.trim().to_uppercase().as_str() {
            "FIN" => flags |= TcpFlags::FIN,
            "SYN" => flags |= TcpFlags::SYN,
            "RST" => flags |= TcpFlags::RST,
            "PSH" => flags |= TcpFlags::PSH,
            "ACK" => flags |= TcpFlags::ACK,
            "URG" => flags |= TcpFlags::URG,
            "ECE" => flags |= TcpFlags::ECE,
            "CWR" => flags |= TcpFlags::CWR,
            other => {
                eprintln!("Warning: Unrecognized TCP flag '{}'", other);
            }
        }
    }
    flags
}

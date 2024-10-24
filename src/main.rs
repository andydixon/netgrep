use clap::{App, Arg};
use hexdump;
use pcap::{Capture, Device};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpPacket},
    udp::UdpPacket,
    Packet,
};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

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
                .help("Filter packets with source IP (use !IP to exclude)"),
        )
        .arg(
            Arg::new("dst_ip")
                .long("dst-ip")
                .value_name("DST_IP")
                .help("Filter packets with destination IP (use !IP to exclude)"),
        )
        .arg(
            Arg::new("content")
                .long("content")
                .value_name("CONTENT")
                .help("Filter packets containing specific content (use !CONTENT to exclude)"),
        )
        .arg(
            Arg::new("tcp_flags")
                .long("tcp-flags")
                .value_name("FLAGS")
                .help(
                    "Filter TCP packets with specific TCP flags (e.g., SYN,ACK; use !FLAGS to exclude)",
                ),
        )
        .arg(
            Arg::new("src_port")
                .long("src-port")
                .value_name("SRC_PORT")
                .help("Filter packets with source port (use !PORT to exclude)"),
        )
        .arg(
            Arg::new("dst_port")
                .long("dst-port")
                .value_name("DST_PORT")
                .help("Filter packets with destination port (use !PORT to exclude)"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .help("Filter packets with source or destination port (use !PORT to exclude)"),
        )
        .get_matches();

    let src_ip = matches.value_of("src_ip");
    let dst_ip = matches.value_of("dst_ip");
    let content = matches.value_of("content");
    let tcp_flags = matches.value_of("tcp_flags");
    let src_port = matches.value_of("src_port");
    let dst_port = matches.value_of("dst_port");
    let port = matches.value_of("port");

    // Open the default device
    let mut cap = Device::lookup()
        .expect("Failed to lookup device")
        .open()
        .expect("Failed to open device");

    while let Ok(packet) = cap.next() {
        // Get the timestamp from the packet header
        let timestamp = packet.header.ts;

        // Parse Ethernet header
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    // Parse IPv4 header
                    if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                        match ip_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                // Handle TCP packet
                                handle_tcp_packet(
                                    &ip_packet,
                                    src_ip,
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    port,
                                    content,
                                    tcp_flags,
                                    packet.data,
                                    timestamp,
                                );
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packet
                                handle_udp_packet(
                                    &ip_packet,
                                    src_ip,
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    port,
                                    content,
                                    packet.data,
                                    timestamp,
                                );
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
                                // Handle TCP packet
                                handle_tcp_packet_ipv6(
                                    &ip_packet,
                                    src_ip,
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    port,
                                    content,
                                    tcp_flags,
                                    packet.data,
                                    timestamp,
                                );
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packet
                                handle_udp_packet_ipv6(
                                    &ip_packet,
                                    src_ip,
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    port,
                                    content,
                                    packet.data,
                                    timestamp,
                                );
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

// Function to handle TCP packets (IPv4)
fn handle_tcp_packet(
    ip_packet: &Ipv4Packet,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    src_port: Option<&str>,
    dst_port: Option<&str>,
    port: Option<&str>,
    content: Option<&str>,
    tcp_flags: Option<&str>,
    packet_data: &[u8],
    timestamp: pcap::TimeVal,
) {
    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
        // Extract information
        let packet_src_ip = IpAddr::V4(ip_packet.get_source());
        let packet_dst_ip = IpAddr::V4(ip_packet.get_destination());
        let packet_src_port = tcp_packet.get_source();
        let packet_dst_port = tcp_packet.get_destination();
        let packet_tcp_flags = tcp_packet.get_flags();
        let packet_payload = tcp_packet.payload();

        let mut matched = true;

        // Apply filters
        matched = apply_filters(
            &packet_src_ip,
            &packet_dst_ip,
            packet_src_port,
            packet_dst_port,
            packet_payload,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            port,
            content,
            matched,
        );

        // Check TCP flags
        if let Some(filter_tcp_flags_str) = tcp_flags {
            let is_not = filter_tcp_flags_str.starts_with('!');
            let filter_tcp_flags_str = filter_tcp_flags_str.trim_start_matches('!');
            let filter_tcp_flags = parse_tcp_flags(filter_tcp_flags_str);
            let flags_match = (packet_tcp_flags & filter_tcp_flags) == filter_tcp_flags;
            if is_not {
                if flags_match {
                    matched = false;
                }
            } else {
                if !flags_match {
                    matched = false;
                }
            }
        }

        // Perform hexdump if all criteria matched
        if matched {
            print_packet_info(
                timestamp,
                &packet_src_ip,
                packet_src_port,
                &packet_dst_ip,
                packet_dst_port,
            );
            hexdump::hexdump(packet_data);
        }
    }
}

// Function to handle UDP packets (IPv4)
fn handle_udp_packet(
    ip_packet: &Ipv4Packet,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    src_port: Option<&str>,
    dst_port: Option<&str>,
    port: Option<&str>,
    content: Option<&str>,
    packet_data: &[u8],
    timestamp: pcap::TimeVal,
) {
    if let Some(udp_packet) = UdpPacket::new(ip_packet.payload()) {
        // Extract information
        let packet_src_ip = IpAddr::V4(ip_packet.get_source());
        let packet_dst_ip = IpAddr::V4(ip_packet.get_destination());
        let packet_src_port = udp_packet.get_source();
        let packet_dst_port = udp_packet.get_destination();
        let packet_payload = udp_packet.payload();

        let mut matched = true;

        // Apply filters
        matched = apply_filters(
            &packet_src_ip,
            &packet_dst_ip,
            packet_src_port,
            packet_dst_port,
            packet_payload,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            port,
            content,
            matched,
        );

        // Perform hexdump if all criteria matched
        if matched {
            print_packet_info(
                timestamp,
                &packet_src_ip,
                packet_src_port,
                &packet_dst_ip,
                packet_dst_port,
            );
            hexdump::hexdump(packet_data);
        }
    }
}

// Function to handle TCP packets (IPv6)
fn handle_tcp_packet_ipv6(
    ip_packet: &Ipv6Packet,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    src_port: Option<&str>,
    dst_port: Option<&str>,
    port: Option<&str>,
    content: Option<&str>,
    tcp_flags: Option<&str>,
    packet_data: &[u8],
    timestamp: pcap::TimeVal,
) {
    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
        // Extract information
        let packet_src_ip = IpAddr::V6(ip_packet.get_source());
        let packet_dst_ip = IpAddr::V6(ip_packet.get_destination());
        let packet_src_port = tcp_packet.get_source();
        let packet_dst_port = tcp_packet.get_destination();
        let packet_tcp_flags = tcp_packet.get_flags();
        let packet_payload = tcp_packet.payload();

        let mut matched = true;

        // Apply filters
        matched = apply_filters(
            &packet_src_ip,
            &packet_dst_ip,
            packet_src_port,
            packet_dst_port,
            packet_payload,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            port,
            content,
            matched,
        );

        // Check TCP flags
        if let Some(filter_tcp_flags_str) = tcp_flags {
            let is_not = filter_tcp_flags_str.starts_with('!');
            let filter_tcp_flags_str = filter_tcp_flags_str.trim_start_matches('!');
            let filter_tcp_flags = parse_tcp_flags(filter_tcp_flags_str);
            let flags_match = (packet_tcp_flags & filter_tcp_flags) == filter_tcp_flags;
            if is_not {
                if flags_match {
                    matched = false;
                }
            } else {
                if !flags_match {
                    matched = false;
                }
            }
        }

        // Perform hexdump if all criteria matched
        if matched {
            print_packet_info(
                timestamp,
                &packet_src_ip,
                packet_src_port,
                &packet_dst_ip,
                packet_dst_port,
            );
            hexdump::hexdump(packet_data);
        }
    }
}

// Function to handle UDP packets (IPv6)
fn handle_udp_packet_ipv6(
    ip_packet: &Ipv6Packet,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    src_port: Option<&str>,
    dst_port: Option<&str>,
    port: Option<&str>,
    content: Option<&str>,
    packet_data: &[u8],
    timestamp: pcap::TimeVal,
) {
    if let Some(udp_packet) = UdpPacket::new(ip_packet.payload()) {
        // Extract information
        let packet_src_ip = IpAddr::V6(ip_packet.get_source());
        let packet_dst_ip = IpAddr::V6(ip_packet.get_destination());
        let packet_src_port = udp_packet.get_source();
        let packet_dst_port = udp_packet.get_destination();
        let packet_payload = udp_packet.payload();

        let mut matched = true;

        // Apply filters
        matched = apply_filters(
            &packet_src_ip,
            &packet_dst_ip,
            packet_src_port,
            packet_dst_port,
            packet_payload,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            port,
            content,
            matched,
        );

        // Perform hexdump if all criteria matched
        if matched {
            print_packet_info(
                timestamp,
                &packet_src_ip,
                packet_src_port,
                &packet_dst_ip,
                packet_dst_port,
            );
            hexdump::hexdump(packet_data);
        }
    }
}

// Function to apply common filters
fn apply_filters(
    packet_src_ip: &IpAddr,
    packet_dst_ip: &IpAddr,
    packet_src_port: u16,
    packet_dst_port: u16,
    packet_payload: &[u8],
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    src_port: Option<&str>,
    dst_port: Option<&str>,
    port: Option<&str>,
    content: Option<&str>,
    mut matched: bool,
) -> bool {
    // Check source IP
    if let Some(filter_src_ip_str) = src_ip {
        let is_not = filter_src_ip_str.starts_with('!');
        let filter_src_ip_str = filter_src_ip_str.trim_start_matches('!');
        match filter_src_ip_str.parse::<IpAddr>() {
            Ok(filter_src_ip) => {
                if is_not {
                    if packet_src_ip == &filter_src_ip {
                        matched = false;
                    }
                } else {
                    if packet_src_ip != &filter_src_ip {
                        matched = false;
                    }
                }
            }
            Err(_) => {
                eprintln!("Invalid source IP address: {}", filter_src_ip_str);
                matched = false;
            }
        }
    }

    // Check destination IP
    if let Some(filter_dst_ip_str) = dst_ip {
        let is_not = filter_dst_ip_str.starts_with('!');
        let filter_dst_ip_str = filter_dst_ip_str.trim_start_matches('!');
        match filter_dst_ip_str.parse::<IpAddr>() {
            Ok(filter_dst_ip) => {
                if is_not {
                    if packet_dst_ip == &filter_dst_ip {
                        matched = false;
                    }
                } else {
                    if packet_dst_ip != &filter_dst_ip {
                        matched = false;
                    }
                }
            }
            Err(_) => {
                eprintln!("Invalid destination IP address: {}", filter_dst_ip_str);
                matched = false;
            }
        }
    }

    // Check source port
    if let Some(filter_src_port_str) = src_port {
        let is_not = filter_src_port_str.starts_with('!');
        let filter_src_port_str = filter_src_port_str.trim_start_matches('!');
        match filter_src_port_str.parse::<u16>() {
            Ok(filter_src_port) => {
                if is_not {
                    if packet_src_port == filter_src_port {
                        matched = false;
                    }
                } else {
                    if packet_src_port != filter_src_port {
                        matched = false;
                    }
                }
            }
            Err(_) => {
                eprintln!("Invalid source port number: {}", filter_src_port_str);
                matched = false;
            }
        }
    }

    // Check destination port
    if let Some(filter_dst_port_str) = dst_port {
        let is_not = filter_dst_port_str.starts_with('!');
        let filter_dst_port_str = filter_dst_port_str.trim_start_matches('!');
        match filter_dst_port_str.parse::<u16>() {
            Ok(filter_dst_port) => {
                if is_not {
                    if packet_dst_port == filter_dst_port {
                        matched = false;
                    }
                } else {
                    if packet_dst_port != filter_dst_port {
                        matched = false;
                    }
                }
            }
            Err(_) => {
                eprintln!("Invalid destination port number: {}", filter_dst_port_str);
                matched = false;
            }
        }
    }

    // Check port (either source or destination)
    if let Some(filter_port_str) = port {
        let is_not = filter_port_str.starts_with('!');
        let filter_port_str = filter_port_str.trim_start_matches('!');
        match filter_port_str.parse::<u16>() {
            Ok(filter_port) => {
                let port_match =
                    packet_src_port == filter_port || packet_dst_port == filter_port;
                if is_not {
                    if port_match {
                        matched = false;
                    }
                } else {
                    if !port_match {
                        matched = false;
                    }
                }
            }
            Err(_) => {
                eprintln!("Invalid port number: {}", filter_port_str);
                matched = false;
            }
        }
    }

    // Check packet content
    if let Some(filter_content_str) = content {
        let is_not = filter_content_str.starts_with('!');
        let filter_content = filter_content_str.trim_start_matches('!');
        let content_bytes = filter_content.as_bytes();
        let content_found = packet_payload
            .windows(content_bytes.len())
            .any(|window| window == content_bytes);

        if is_not {
            if content_found {
                matched = false;
            }
        } else {
            if !content_found {
                matched = false;
            }
        }
    }

    matched
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

// Function to print packet information before the hexdump
fn print_packet_info(
    timestamp: pcap::TimeVal,
    src_ip: &IpAddr,
    src_port: u16,
    dst_ip: &IpAddr,
    dst_port: u16,
) {
    // Convert timestamp to SystemTime
    let ts_secs = timestamp.tv_sec as u64;
    let ts_usecs = timestamp.tv_usec as u64;
    let duration_since_epoch = std::time::Duration::new(ts_secs, (ts_usecs * 1000) as u32);
    let system_time = UNIX_EPOCH + duration_since_epoch;

    // Format timestamp
    let datetime: chrono::DateTime<chrono::Local> = system_time.into();
    let formatted_time = datetime.format("[%Y-%m-%d %H:%M:%S%.6f]").to_string();

    // Print packet info
    println!(
        "[{}] Source: {} Port: {} - Destination: {} Port: {}",
        formatted_time, src_ip, src_port, dst_ip, dst_port
    );
}

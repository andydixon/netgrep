use clap::{App, Arg};
use hexdump;
use libc;
use pcap::Device;
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
use std::time::UNIX_EPOCH;

fn main() {
    // Parse command-line arguments
    let matches = App::new("netgrep")
        .version("1.0")
        .author("Andy Dixon")
        .about("Filters packets based on criteria and performs a hexdump")
        .arg(
            Arg::new("src_ip")
                .long("src-ip")
                .value_name("SRC_IP")
                .help("Filter packets with source IP(s) (use !IP to exclude, comma-separated for multiple IPs)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .arg(
            Arg::new("dst_ip")
                .long("dst-ip")
                .value_name("DST_IP")
                .help("Filter packets with destination IP(s) (use !IP to exclude, comma-separated for multiple IPs)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .arg(
            Arg::new("content")
                .long("content")
                .value_name("CONTENT")
                .help("Filter packets containing specific content(s) (use !CONTENT to exclude, comma-separated for multiple contents)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .arg(
            Arg::new("tcp_flags")
                .long("tcp-flags")
                .value_name("FLAGS")
                .help("Filter TCP packets with specific TCP flags (e.g., SYN,ACK; use !FLAGS to exclude, comma-separated for multiple sets)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .arg(
            Arg::new("src_port")
                .long("src-port")
                .value_name("SRC_PORT")
                .help("Filter packets with source port(s) (use !PORT to exclude, comma-separated for multiple ports)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .arg(
            Arg::new("dst_port")
                .long("dst-port")
                .value_name("DST_PORT")
                .help("Filter packets with destination port(s) (use !PORT to exclude, comma-separated for multiple ports)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .help("Filter packets with source or destination port(s) (use !PORT to exclude, comma-separated for multiple ports)")
                .takes_value(true)
                .use_delimiter(true),
        )
        .get_matches();

    let src_ips = matches
        .get_many::<String>("src_ip")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());
    let dst_ips = matches
        .get_many::<String>("dst_ip")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());
    let contents = matches
        .get_many::<String>("content")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());
    let tcp_flags_list = matches
        .get_many::<String>("tcp_flags")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());
    let src_ports = matches
        .get_many::<String>("src_port")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());
    let dst_ports = matches
        .get_many::<String>("dst_port")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());
    let ports = matches
        .get_many::<String>("port")
        .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>());

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
                                    &src_ips,
                                    &dst_ips,
                                    &src_ports,
                                    &dst_ports,
                                    &ports,
                                    &contents,
                                    &tcp_flags_list,
                                    packet.data,
                                    timestamp,
                                );
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packet
                                handle_udp_packet(
                                    &ip_packet,
                                    &src_ips,
                                    &dst_ips,
                                    &src_ports,
                                    &dst_ports,
                                    &ports,
                                    &contents,
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
                                    &src_ips,
                                    &dst_ips,
                                    &src_ports,
                                    &dst_ports,
                                    &ports,
                                    &contents,
                                    &tcp_flags_list,
                                    packet.data,
                                    timestamp,
                                );
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packet
                                handle_udp_packet_ipv6(
                                    &ip_packet,
                                    &src_ips,
                                    &dst_ips,
                                    &src_ports,
                                    &dst_ports,
                                    &ports,
                                    &contents,
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
    src_ips: &Option<Vec<&str>>,
    dst_ips: &Option<Vec<&str>>,
    src_ports: &Option<Vec<&str>>,
    dst_ports: &Option<Vec<&str>>,
    ports: &Option<Vec<&str>>,
    contents: &Option<Vec<&str>>,
    tcp_flags_list: &Option<Vec<&str>>,
    packet_data: &[u8],
    timestamp: libc::timeval,
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
            src_ips,
            dst_ips,
            src_ports,
            dst_ports,
            ports,
            contents,
            matched,
        );

        // Check TCP flags
        if let Some(tcp_flags_list) = tcp_flags_list {
            let mut flag_matched = false;
            let mut any_invalid = false;
            for filter_tcp_flags_str in tcp_flags_list {
                let is_not = filter_tcp_flags_str.starts_with('!');
                let filter_tcp_flags_str = filter_tcp_flags_str.trim_start_matches('!');
                let filter_tcp_flags = parse_tcp_flags(filter_tcp_flags_str);
                if filter_tcp_flags == 0 {
                    eprintln!("Invalid TCP flags: {}", filter_tcp_flags_str);
                    any_invalid = true;
                    break;
                }
                let flags_match = (packet_tcp_flags & filter_tcp_flags) == filter_tcp_flags;
                if is_not {
                    if flags_match {
                        matched = false;
                        break;
                    }
                } else {
                    if flags_match {
                        flag_matched = true;
                    }
                }
            }
            if any_invalid {
                matched = false;
            } else if !flag_matched && tcp_flags_list.iter().all(|s| !s.starts_with('!')) {
                matched = false;
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
    src_ips: &Option<Vec<&str>>,
    dst_ips: &Option<Vec<&str>>,
    src_ports: &Option<Vec<&str>>,
    dst_ports: &Option<Vec<&str>>,
    ports: &Option<Vec<&str>>,
    contents: &Option<Vec<&str>>,
    packet_data: &[u8],
    timestamp: libc::timeval,
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
            src_ips,
            dst_ips,
            src_ports,
            dst_ports,
            ports,
            contents,
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
    src_ips: &Option<Vec<&str>>,
    dst_ips: &Option<Vec<&str>>,
    src_ports: &Option<Vec<&str>>,
    dst_ports: &Option<Vec<&str>>,
    ports: &Option<Vec<&str>>,
    contents: &Option<Vec<&str>>,
    tcp_flags_list: &Option<Vec<&str>>,
    packet_data: &[u8],
    timestamp: libc::timeval,
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
            src_ips,
            dst_ips,
            src_ports,
            dst_ports,
            ports,
            contents,
            matched,
        );

        // Check TCP flags
        if let Some(tcp_flags_list) = tcp_flags_list {
            let mut flag_matched = false;
            let mut any_invalid = false;
            for filter_tcp_flags_str in tcp_flags_list {
                let is_not = filter_tcp_flags_str.starts_with('!');
                let filter_tcp_flags_str = filter_tcp_flags_str.trim_start_matches('!');
                let filter_tcp_flags = parse_tcp_flags(filter_tcp_flags_str);
                if filter_tcp_flags == 0 {
                    eprintln!("Invalid TCP flags: {}", filter_tcp_flags_str);
                    any_invalid = true;
                    break;
                }
                let flags_match = (packet_tcp_flags & filter_tcp_flags) == filter_tcp_flags;
                if is_not {
                    if flags_match {
                        matched = false;
                        break;
                    }
                } else {
                    if flags_match {
                        flag_matched = true;
                    }
                }
            }
            if any_invalid {
                matched = false;
            } else if !flag_matched && tcp_flags_list.iter().all(|s| !s.starts_with('!')) {
                matched = false;
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
    src_ips: &Option<Vec<&str>>,
    dst_ips: &Option<Vec<&str>>,
    src_ports: &Option<Vec<&str>>,
    dst_ports: &Option<Vec<&str>>,
    ports: &Option<Vec<&str>>,
    contents: &Option<Vec<&str>>,
    packet_data: &[u8],
    timestamp: libc::timeval,
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
            src_ips,
            dst_ips,
            src_ports,
            dst_ports,
            ports,
            contents,
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
    src_ips: &Option<Vec<&str>>,
    dst_ips: &Option<Vec<&str>>,
    src_ports: &Option<Vec<&str>>,
    dst_ports: &Option<Vec<&str>>,
    ports: &Option<Vec<&str>>,
    contents: &Option<Vec<&str>>,
    mut matched: bool,
) -> bool {
    // Helper function to parse include and exclude lists
    fn parse_include_exclude<T: std::str::FromStr>(
        values: &[&str],
    ) -> Result<(Vec<T>, Vec<T>), String> {
        let mut include_list = Vec::new();
        let mut exclude_list = Vec::new();

        for val_str in values {
            let is_not = val_str.starts_with('!');
            let val_str_trimmed = val_str.trim_start_matches('!');
            match val_str_trimmed.parse::<T>() {
                Ok(val) => {
                    if is_not {
                        exclude_list.push(val);
                    } else {
                        include_list.push(val);
                    }
                }
                Err(_) => {
                    return Err(format!("Invalid value: {}", val_str_trimmed));
                }
            }
        }

        Ok((include_list, exclude_list))
    }

    // Source IPs
    if let Some(filter_src_ip_list) = src_ips {
        match parse_include_exclude::<IpAddr>(filter_src_ip_list) {
            Ok((include_ips, exclude_ips)) => {
                if exclude_ips.contains(packet_src_ip) {
                    matched = false;
                }
                if !include_ips.is_empty() && !include_ips.contains(packet_src_ip) {
                    matched = false;
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                matched = false;
            }
        }
    }

    // Destination IPs
    if let Some(filter_dst_ip_list) = dst_ips {
        match parse_include_exclude::<IpAddr>(filter_dst_ip_list) {
            Ok((include_ips, exclude_ips)) => {
                if exclude_ips.contains(packet_dst_ip) {
                    matched = false;
                }
                if !include_ips.is_empty() && !include_ips.contains(packet_dst_ip) {
                    matched = false;
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                matched = false;
            }
        }
    }

    // Source Ports
    if let Some(filter_src_port_list) = src_ports {
        match parse_include_exclude::<u16>(filter_src_port_list) {
            Ok((include_ports, exclude_ports)) => {
                if exclude_ports.contains(&packet_src_port) {
                    matched = false;
                }
                if !include_ports.is_empty() && !include_ports.contains(&packet_src_port) {
                    matched = false;
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                matched = false;
            }
        }
    }

    // Destination Ports
    if let Some(filter_dst_port_list) = dst_ports {
        match parse_include_exclude::<u16>(filter_dst_port_list) {
            Ok((include_ports, exclude_ports)) => {
                if exclude_ports.contains(&packet_dst_port) {
                    matched = false;
                }
                if !include_ports.is_empty() && !include_ports.contains(&packet_dst_port) {
                    matched = false;
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                matched = false;
            }
        }
    }

    // Ports (either source or destination)
    if let Some(filter_port_list) = ports {
        match parse_include_exclude::<u16>(filter_port_list) {
            Ok((include_ports, exclude_ports)) => {
                let port_match = include_ports.iter().any(|&p| p == packet_src_port || p == packet_dst_port);
                let port_exclude = exclude_ports.iter().any(|&p| p == packet_src_port || p == packet_dst_port);
                if port_exclude {
                    matched = false;
                }
                if !include_ports.is_empty() && !port_match {
                    matched = false;
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                matched = false;
            }
        }
    }

    // Content
    if let Some(filter_content_list) = contents {
        let mut content_matched = false;
        let mut any_invalid = false;
        for filter_content_str in filter_content_list {
            let is_not = filter_content_str.starts_with('!');
            let filter_content = filter_content_str.trim_start_matches('!');
            let content_bytes = filter_content.as_bytes();
            let content_found = packet_payload
                .windows(content_bytes.len())
                .any(|window| window == content_bytes);

            if is_not {
                if content_found {
                    matched = false;
                    break;
                }
            } else {
                if content_found {
                    content_matched = true;
                }
            }
        }
        if any_invalid {
            matched = false;
        } else if !content_matched && filter_content_list.iter().all(|s| !s.starts_with('!')) {
            matched = false;
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
    timestamp: libc::timeval,
    src_ip: &IpAddr,
    src_port: u16,
    dst_ip: &IpAddr,
    dst_port: u16,
) {
    // Convert timestamp to SystemTime
    let ts_secs = timestamp.tv_sec as u64;
    let ts_usecs = timestamp.tv_usec as u32;
    let duration_since_epoch = std::time::Duration::new(ts_secs, ts_usecs * 1000);
    let system_time = UNIX_EPOCH + duration_since_epoch;

    // Format timestamp
    let datetime: chrono::DateTime<chrono::Local> = system_time.into();
    let formatted_time = datetime.format("[%Y-%m-%d %H:%M:%S%.6f]").to_string();

    // Print packet info
    println!(
        "{} Source: {} Port: {} - Destination: {} Port: {}",
        formatted_time, src_ip, src_port, dst_ip, dst_port
    );
}

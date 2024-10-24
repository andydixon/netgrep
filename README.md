# netgrep
_(c) 2024- Andy Dixon (andy @ andydixon.com)_

A Rust-based packet filtering tool that captures network packets and performs a hexdump of packets matching specified criteria. The tool supports filtering by source IP, destination IP, source port, destination port, TCP flags, and packet content. It handles both IPv4 and IPv6 packets.

## Features

* Capture packets from the default network interface.
* Filter packets based on:
  * Source IP address (--src-ip)
  * Destination IP address (--dst-ip)
  * Source port (--src-port)
  * Destination port (--dst-port)
  * Either source or destination port (--port)
  * TCP flags (--tcp-flags)
  * Packet content (--content)
* Supports both IPv4 and IPv6 packets.
* Performs a hexdump of matching packets using the hexdump crate.

## Requirements

* Rust (latest stable version recommended)
* Cargo (Rust's package manager)

Dependencies

* pcap - For capturing network packets.
* pnet_packet - For parsing network packets.
* hexdump - For displaying packet data in hexadecimal format.
* clap - For command-line argument parsing.

## Installation

    git clone https://github.com/andydixon/netgrep.git
    cd packet-filter
    cargo build --release

This will create an executable in the target/release directory.

## Usage

Run the program with desired filtering options. If no options are provided, the tool will capture and hexdump all TCP packets.

    cargo run -- [OPTIONS]

Note: You may need administrative privileges to capture network packets. On Unix-based systems, you can run the program with sudo:

    sudo cargo run -- [OPTIONS]

### Options

    --src-ip <SRC_IP>: Filter packets with the specified source IP address.
    --dst-ip <DST_IP>: Filter packets with the specified destination IP address.
    --src-port <SRC_PORT>: Filter packets with the specified source port.
    --dst-port <DST_PORT>: Filter packets with the specified destination port.
    --port <PORT>: Filter packets where either the source or destination port matches the specified port.
    --tcp-flags <FLAGS>: Filter packets with specific TCP flags set (e.g., SYN, ACK). Multiple flags can be specified, separated by commas.
    --content <CONTENT>: Filter packets containing the specified content in their payload.

### Examples

NOTE: The inverse can be applied by prefixing with an exclamation point.

Filter by Source IP:

    sudo cargo run -- --src-ip 192.168.1.10

Filter by Destination IP (IPv6):

    sudo cargo run -- --dst-ip fe80::1ff:fe23:4567:890a

Filter by Source Port:

    sudo cargo run -- --src-port 80

Filter by Destination Port:

    sudo cargo run -- --dst-port 443

Filter by Port (Either Source or Destination):

    sudo cargo run -- --port !22

Filter by TCP Flags:

    sudo cargo run -- --tcp-flags SYN,ACK

Filter by Packet Content:

    sudo cargo run -- --content "password"

Combine Multiple Filters:

    sudo cargo run -- --src-ip 192.168.1.10 --dst-port 80 --tcp-flags SYN

## License

This project is licensed under the GNU General Public License v3.0. You can find the full text of the license in the LICENSE file or at GNU GPL v3.0.

## Disclaimer

* Administrative Privileges: Capturing network packets typically requires administrative privileges. Ensure you understand the security implications of running software with elevated permissions.
* Network Usage Policies: Always make sure you have permission to capture network traffic on the networks you are monitoring. Unauthorized interception of network traffic may violate laws and regulations.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For questions or suggestions, please open an issue on the GitHub repository.

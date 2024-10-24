# netgrep

A Rust-based packet filtering tool that captures network packets and performs a hexdump of packets matching specified criteria. The tool supports filtering by source IP, destination IP, source port, destination port, TCP flags, and packet content. It handles both IPv4 and IPv6 packets and supports both TCP and UDP protocols.

## Authors and Contributors
Andy Dixon - [Github](https://www.github.com/andydixon) - [Web](https://www.andydixon.com/)

## Features

- **Capture Packets**: Captures packets from the default network interface.
- **Protocol Support**: Supports both TCP and UDP packets over IPv4 and IPv6.
- **Filtering Options**:
- **Source IP Address (`--src-ip`)**: Filter packets by source IP(s).
- **Destination IP Address (`--dst-ip`)**: Filter packets by destination IP(s).
- **Source Port (`--src-port`)**: Filter packets by source port(s).
- **Destination Port (`--dst-port`)**: Filter packets by destination port(s).
- **Port (`--port`)**: Filter packets by source or destination port(s).
- **TCP Flags (`--tcp-flags`)**: Filter TCP packets by specific TCP flags.
- **Packet Content (`--content`)**: Filter packets containing specific content(s).
- **'Not' Operator**: Use the 'not' operator (`!`) to exclude specific values in filters.
- **Multiple Values**: Specify multiple values for each filter option using commas.
- **Packet Information**: Before each hexdump, the tool prints a line with the timestamp, source IP, source port, destination IP, and destination port.
- **Hexdump**: Performs a hexdump of matching packets using the `hexdump` crate.

## Requirements

- **Rust**: Latest stable version recommended.
- **Cargo**: Rust's package manager.

## Dependencies

- [`pcap`](https://crates.io/crates/pcap) - For capturing network packets.
- [`pnet_packet`](https://crates.io/crates/pnet_packet) - For parsing network packets.
- [`hexdump`](https://crates.io/crates/hexdump) - For displaying packet data in hexadecimal format.
- [`clap`](https://crates.io/crates/clap) - For command-line argument parsing.
- [`chrono`](https://crates.io/crates/chrono) - For timestamp formatting.

## Installation

1. **Clone the Repository**

 ```bash
 git clone https://github.com/yourusername/packet-filter.git
 cd packet-filter
 ```

2. **Build the Project**

Use Cargo to build the project:

 ```bash
 cargo build --release
 ```

This will create an executable in the `target/release` directory.

## Usage

Run the program with desired filtering options. If no options are provided, the tool will capture and hexdump all TCP and UDP packets.

```bash
cargo run -- [OPTIONS]
```

**Note:** You may need administrative privileges to capture network packets. On Unix-based systems, you can run the program with `sudo`:

```bash
sudo cargo run -- [OPTIONS]
```

### Options

- `--src-ip <SRC_IP>`: Filter packets with the specified source IP address(es). Use `!IP` to exclude packets from that IP. Multiple IPs can be specified, separated by commas.

- `--dst-ip <DST_IP>`: Filter packets with the specified destination IP address(es). Use `!IP` to exclude packets to that IP. Multiple IPs can be specified, separated by commas.

- `--src-port <SRC_PORT>`: Filter packets with the specified source port(s). Use `!PORT` to exclude packets from that port. Multiple ports can be specified, separated by commas.

- `--dst-port <DST_PORT>`: Filter packets with the specified destination port(s). Use `!PORT` to exclude packets to that port. Multiple ports can be specified, separated by commas.

- `--port <PORT>`: Filter packets where either the source or destination port matches the specified port(s). Use `!PORT` to exclude packets involving that port. Multiple ports can be specified, separated by commas.

- `--tcp-flags <FLAGS>`: Filter TCP packets with specific TCP flags set (e.g., `SYN,ACK`). Use `!FLAGS` to exclude packets with those flags. Multiple flag sets can be specified, separated by commas.

- `--content <CONTENT>`: Filter packets containing the specified content(s) in their payload. Use `!CONTENT` to exclude packets containing that content. Multiple contents can be specified, separated by commas.

### Output Format

For each matching packet, the program outputs:

```
[timestamp] Source: [source IP] Port: [source port] - Destination: [destination IP] Port: [destination port]
[Hexdump of the packet]
```

**Example:**

```
[2024-10-24 14:23:45.123456] Source: 192.168.1.100 Port: 443 - Destination: 192.168.1.10 Port: 52345
0000: 16 03 03 00 4b 02 00 00 47 03 03 5f e2 53 05 34 ....K...G.._.S.4
0010: e1 8b 9c f6 68 3d 71 38 9f 1f 75 e3 86 0f 38 74 ....h=q8..u...8t
...
```

### Multiple Values

You can specify multiple values for each filter option by separating them with commas. The 'not' operator (`!`) can be applied to individual values.

#### Examples:

- **Filter packets from multiple source IPs:**

 ```bash
 sudo cargo run -- --src-ip 192.168.1.10,10.0.0.1
 ```

- **Exclude packets to multiple destination IPs:**

 ```bash
 sudo cargo run -- --dst-ip '!192.168.1.20',!10.0.0.2
 ```

- **Filter packets on multiple ports:**

 ```bash
 sudo cargo run -- --port 80,443,22
 ```

- **Exclude packets from specific ports:**

 ```bash
 sudo cargo run -- --port '!25',!110
 ```

- **Filter packets with multiple TCP flags:**

 ```bash
 sudo cargo run -- --tcp-flags SYN --tcp-flags ACK
 ```

- **Filter packets containing specific contents:**

 ```bash
 sudo cargo run -- --content "password","login"
 ```

- **Exclude packets containing specific contents:**

 ```bash
 sudo cargo run -- --content '!token','!secret'
 ```

### 'Not' Operator

The 'not' operator (`!`) can be used to exclude specific values from filters. Apply it directly before the value without any spaces.

#### Examples:

- **Exclude packets from source IP 192.168.1.10:**

 ```bash
 sudo cargo run -- --src-ip '!192.168.1.10'
 ```

- **Exclude packets to destination port 443:**

 ```bash
 sudo cargo run -- --dst-port '!443'
 ```

- **Exclude packets with the SYN TCP flag set:**

 ```bash
 sudo cargo run -- --tcp-flags '!SYN'
 ```

- **Exclude packets containing "error":**

 ```bash
 sudo cargo run -- --content '!error'
 ```

### Protocol Support

The program supports both **TCP** and **UDP** packets. Filters for IP addresses, ports, and content apply to both TCP and UDP packets. The `--tcp-flags` option applies only to TCP packets.

#### Examples:

- **Filter UDP packets to destination port 53 (DNS):**

 ```bash
 sudo cargo run -- --dst-port 53
 ```

- **Exclude UDP packets from source port 123 (NTP):**

 ```bash
 sudo cargo run -- --src-port '!123'
 ```

### Combined Filters

You can combine multiple filters to refine your packet selection.

#### Examples:

- **Filter TCP packets from specific source IPs and ports with SYN flag:**

 ```bash
 sudo cargo run -- --src-ip 192.168.1.10,10.0.0.1 --src-port 1000,2000 --tcp-flags SYN
 ```

- **Exclude packets to specific destinations and containing certain contents:**

 ```bash
 sudo cargo run -- --dst-ip '!192.168.1.20',!10.0.0.2 --content '!token','!password'
 ```

## License

This project is licensed under the GNU General Public License v3.0. You can find the full text of the license in the [LICENSE](LICENSE) file or at [GNU GPL v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Disclaimer

- **Administrative Privileges:** Capturing network packets typically requires administrative privileges. Ensure you understand the security implications of running software with elevated permissions.
- **Network Usage Policies:** Always make sure you have permission to capture network traffic on the networks you are monitoring. Unauthorized interception of network traffic may violate laws and regulations.
- **Ethical Use:** This tool is intended for educational and authorized testing purposes only. Misuse of this tool may lead to legal consequences.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For questions or suggestions, please open an issue on the GitHub repository.


---

**Important Notes:**

- **No Spaces Around Commas:** When specifying multiple values, do not include spaces around commas.

- Correct: `--src-ip 192.168.1.1,10.0.0.1`
- Incorrect: `--src-ip 192.168.1.1, 10.0.0.1`

- **Quoting Values:** If your shell interprets special characters (like `!`), enclose the value in quotes.

- Example: `--tcp-flags '!SYN'`

- **'Not' Operator Scope:** The 'not' operator applies to individual values within a comma-separated list.

- **Case Sensitivity:** Content matching is case-sensitive. Ensure you use the correct casing for content filters.

- **Invalid Values:** If an invalid value is provided, the program will print an error message and skip processing the current packet.

## Testing the Program

- **Generate Test Traffic:**

- Use tools like `curl`, `telnet`, `dig`, `nslookup`, or `iperf` to generate network traffic that matches specific filters.
- Example: `curl http://example.com` to generate HTTP traffic on port 80.

- **Verify Filters:**

- Run the program with various combinations of filters to ensure it only hexdumps the packets you're interested in.
- Combine inclusion and exclusion filters to refine the packet selection.

## Extensibility

- **Additional Protocols:**

  - The current implementation supports TCP and UDP. I intend to support other protocols like ICMP, but feel free to send a pull request if you wish to contribute.

- **Output Options:**

  - Modify the code to save matching packets to a file or to display a summary instead of a hexdump.
  - Customize the output format as per your requirements.

## Feedback and Issues

If you encounter any issues or have suggestions for improvements, please open an issue on the GitHub repository.

---

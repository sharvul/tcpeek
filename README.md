# tcpeek

A high-performance utility for capturing the first N packets from TCP sessions. This tool is particularly useful when you need to sample the beginning of long TCP sessions without capturing the entire traffic.

## Features

- Capture the first N packets from TCP sessions
- Filter traffic using BPF expressions
- High-performance packet capture using libpcap
- Support for multiple concurrent sessions
- Memory-safe implementation in Rust
- Save captured packets to PCAP files for later analysis

## Requirements

- Rust 1.70 or later
- libpcap development files
- Linux/Unix-like operating system

## Installation

1. Install libpcap development files:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install libpcap-dev
   
   # CentOS/RHEL
   sudo yum install libpcap-devel
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

## Usage

```bash
tcpeek [OPTIONS] --filter <FILTER>

Options:
    -n, --number <NUMBER>    Number of packets to capture per session [default: 10]
    -f, --filter <FILTER>    BPF filter expression
    -i, --interface <IFACE>  Network interface to capture from
    -o, --output <FILE>      Output file to save captured packets (PCAP format)
    -h, --help              Print help information
    -V, --version           Print version information
```

### Examples

1. Capture the first 5 packets from each TCP session on port 80:
   ```bash
   tcpeek -n 5 -f "tcp port 80"
   ```

2. Capture from a specific interface:
   ```bash
   tcpeek -i eth0 -f "tcp port 443"
   ```

3. Save captured packets to a PCAP file:
   ```bash
   tcpeek -n 10 -f "tcp port 80" -o capture.pcap
   ```

## Performance Considerations

- The tool is optimized for high packet rates
- Uses efficient packet parsing and session tracking
- Minimal memory footprint per session
- Automatic cleanup of completed sessions
- Efficient PCAP file writing with minimal overhead

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. # tcpeek

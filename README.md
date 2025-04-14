# TCPeek

A TCP packet capture tool that captures the first N packets from new TCP sessions (starting from the SYN packet).

## Usage

```bash
tcpeek -i <interface> -o <output.pcap> [-n <number>] [-f <filter>]
```

### Options

- `-i, --interface`: Network interface to capture from (required)
- `-o, --output`: Output file to save captured packets (required)
- `-n, --number`: Number of packets to capture per session (default: 20)
- `-f, --filter`: BPF filter expression (default: "tcp")

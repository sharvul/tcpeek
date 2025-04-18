use clap::Parser;
use pcap::{Capture, Device, Linktype};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::collections::HashMap;
use std::sync::Arc;
use ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of packets to capture per session
    #[arg(short, long, default_value_t = 20)]
    number: usize,

    /// BPF filter expression
    #[arg(short, long, default_value_t = String::from("tcp"))]
    filter: String,

    /// Network interface to capture from
    #[arg(short, long)]
    interface: String,

    /// Output file to save captured packets 
    #[arg(short, long)]
    output: String,

    /// Global limit on total packets to capture
    #[arg(short, long, default_value_t = 50000)]
    count: usize,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
struct TCPSessionMetadata {
    client: SocketAddrV4,
    server: SocketAddrV4,
}

impl std::fmt::Display for TCPSessionMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.client, self.server)
    }
}

fn get_ip_header_offset(data: &[u8]) -> Option<usize> {
    // Minimum length for Ethernet header (14 bytes)
    if data.len() < 14 {
        return None;
    }

    // Check for VLAN tag (0x8100)
    let mut offset = 14;
    while data.len() > offset + 4 {
        let ethertype = (data[offset - 2] as u16) << 8 | data[offset - 1] as u16;
        if ethertype == 0x8100 {
            // Found a VLAN tag, add 4 bytes to offset
            offset += 4;
        } else if ethertype == 0x0800 {
            // Found IPv4
            return Some(offset);
        } else {
            // Unknown or unsupported EtherType
            return None;
        }
    }
    None
}

fn parse_packet_data(data: &[u8]) -> Option<(TCPSessionMetadata, bool)> {
    // Get the offset to the IP header, accounting for VLAN tags
    let ip_header_start = match get_ip_header_offset(data) {
        Some(offset) => offset,
        None => return None,
    };
    
    // Ensure we have enough data for IP header
    if data.len() >= ip_header_start + 20 {
        // Extract source and destination IP addresses
        let src_ip = Ipv4Addr::new(
            data[ip_header_start + 12], 
            data[ip_header_start + 13], 
            data[ip_header_start + 14], 
            data[ip_header_start + 15]
        );
        
        let dst_ip = Ipv4Addr::new(
            data[ip_header_start + 16], 
            data[ip_header_start + 17], 
            data[ip_header_start + 18], 
            data[ip_header_start + 19]
        );
        
        // Get IP header length to find start of TCP header
        let ip_header_len = (data[ip_header_start] & 0x0F) * 4;
        let tcp_header_start = ip_header_start + ip_header_len as usize;
        
        // Check if protocol is TCP (protocol number 6)
        if data[ip_header_start + 9] == 6 && data.len() >= tcp_header_start + 13 {
            // Extract source and destination ports
            let src_port = ((data[tcp_header_start] as u16) << 8) | data[tcp_header_start + 1] as u16;
            let dst_port = ((data[tcp_header_start + 2] as u16) << 8) | data[tcp_header_start + 3] as u16;
            
            // Check for SYN flag (bit 1 in the flags byte)
            let syn_flag = (data[tcp_header_start + 13] & 0x02) != 0;
            
            if src_port > dst_port {
                // We assume the dst_port is the server port
                return Some((
                    TCPSessionMetadata { 
                        client: SocketAddrV4::new(src_ip, src_port), 
                        server: SocketAddrV4::new(dst_ip, dst_port), 
                    },
                    syn_flag
                ));
            }
            else {
                // We assume the src_port is the server port
                return Some((
                    TCPSessionMetadata { 
                        client: SocketAddrV4::new(dst_ip, dst_port), 
                        server: SocketAddrV4::new(src_ip, src_port), 
                    },
                    syn_flag
                ));
            }
        }
    }
    None
}

fn main() {
    let args = Args::parse();
    println!("tcpeeking on {}...", args.interface);

    let device = Device::try_from(args.interface.as_str()).unwrap();

    let mut capture = Capture::from_device(device)
        .unwrap()
        .buffer_size(16 * 1024 * 1024)  // 16MB buffer
        .snaplen(65535) // Capture full packets
        .timeout(500)
        .open()
        .unwrap()
        .setnonblock()
        .unwrap();
    
    capture.filter(&args.filter, true).unwrap();

    // Initialize PCAP writer
    let mut writer = Capture::dead(Linktype::ETHERNET)
        .unwrap()
        .savefile(&args.output)
        .unwrap();
    
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();
    
    ctrlc::set_handler(move || {
        is_running_clone.store(false, Ordering::SeqCst);
    }).unwrap();

    // Track sessions and their packet counts
    let mut session_packets_counter: HashMap<TCPSessionMetadata, usize> = HashMap::with_capacity(1000);
    
    // Track total packets written
    let mut total_packets_written = 0;

    while is_running.load(Ordering::SeqCst) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((tcp_session_metadata, syn_flag)) = parse_packet_data(packet.data) {
                    // If this is a SYN packet, add session to the session counter
                    if syn_flag && !session_packets_counter.contains_key(&tcp_session_metadata) {
                        session_packets_counter.insert(tcp_session_metadata.clone(), 1);
                        println!("[+++] {}", tcp_session_metadata);
                    }
                    
                    if let Some(session_count) = session_packets_counter.get_mut(&tcp_session_metadata) {
                        if *session_count > args.number {
                            continue;  // Skip if we've already captured enough packets
                        }    
                        else if *session_count == args.number {
                            println!("[---] {}", tcp_session_metadata);
                        }
                        
                        writer.write(&packet);
                        *session_count += 1;
                        total_packets_written += 1;

                        if total_packets_written >= args.count {
                            println!("Reached global packet limit of {}", args.count);
                            break;
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Avoid busy waiting, as we are using non-blocking mode
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                eprintln!("Error capturing packet: {}", e);
                break;
            }
        }
    }

    writer.flush().unwrap();
}

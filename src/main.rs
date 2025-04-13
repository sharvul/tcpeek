use clap::Parser;
use pcap::{Capture, Device, Linktype};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use ctrlc;

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
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
struct TCPSessionMetadata {
    src: SocketAddrV4,
    dst: SocketAddrV4,
}

impl TCPSessionMetadata {
    
    fn from_packet_data(data: &[u8]) -> Option<Self> {
        // Check if we have an IPv4 packet (EtherType 0x0800)
        if data.len() > 14 && data[12] == 0x08 && data[13] == 0x00 {
            // IPv4 header starts at offset 14
            let ip_header_start = 14;
            
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
                if data[ip_header_start + 9] == 6 && data.len() >= tcp_header_start + 4 {
                    // Extract source and destination ports
                    let src_port = ((data[tcp_header_start] as u16) << 8) | data[tcp_header_start + 1] as u16;
                    let dst_port = ((data[tcp_header_start + 2] as u16) << 8) | data[tcp_header_start + 3] as u16;
                    
                    return Some(
                        TCPSessionMetadata { 
                            src: SocketAddrV4::new(src_ip, src_port), 
                            dst: SocketAddrV4::new(dst_ip, dst_port), 
                        }
                    );
                }
            }
        }
        None
    }
    
}

impl std::fmt::Display for TCPSessionMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

fn main() {
    let args = Args::parse();
    println!("tcpeeking on {}...", args.interface);

    let device = Device::try_from(args.interface.as_str()).unwrap();

    let mut capture = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .buffer_size(16 * 1024 * 1024)  // 16MB buffer
        .snaplen(65535)  // Capture full packets
        .timeout(100)  // 100ms timeout
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
    
    // Track sessions and their packet counts
    let mut session_packets_counter: HashMap<TCPSessionMetadata, usize> = HashMap::with_capacity(1000);
    
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();

    ctrlc::set_handler(move || {
        is_running_clone.store(false, Ordering::SeqCst);
    }).unwrap();

    while is_running.load(Ordering::SeqCst) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some(tcp_session_metadata) = TCPSessionMetadata::from_packet_data(packet.data) {
                    let count = session_packets_counter.entry(tcp_session_metadata.clone()).or_insert(1);
                    if *count > args.number {
                        continue;  // Skip if we've already captured enough packets
                    }

                    if *count == 1 {
                        println!("[+++] {}", tcp_session_metadata);
                    }
                    else if *count == args.number {
                        println!("[---] {}", tcp_session_metadata);
                    }
                    
                    writer.write(&packet);
                    *count += 1;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Error capturing packet: {}", e);
                break;
            }
        }
    }

    writer.flush().unwrap();
}

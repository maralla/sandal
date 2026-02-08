use anyhow::Result;
/// User-space network stack (SLIRP-style NAT).
///
/// Provides VM networking **without root privileges** by proxying
/// guest TCP/UDP/ICMP through host-side BSD sockets.
///
/// Virtual network layout:
///   Guest:   10.0.2.15
///   Gateway: 10.0.2.2
///   DNS:     10.0.2.3
///   Netmask: 255.255.255.0
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc;

// ============= NETWORK CONFIGURATION =============

pub const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
pub const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
pub const DNS_IP: [u8; 4] = [10, 0, 2, 3];
pub const NETMASK: [u8; 4] = [255, 255, 255, 0];

const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

const TCP_MSS: usize = 1460; // MTU(1500) - IP(20) - TCP(20)

// ============= ICMP SOCKET FFI =============
// Non-privileged ICMP sockets (SOCK_DGRAM + IPPROTO_ICMP) on macOS.

const ICMP_AF_INET: i32 = 2;
const ICMP_SOCK_DGRAM: i32 = 2;
const ICMP_IPPROTO_ICMP: i32 = 1;
const ICMP_SOL_SOCKET: i32 = 0xFFFF;
const ICMP_SO_RCVTIMEO: i32 = 0x1006;

#[repr(C)]
struct libc_sockaddr_in {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct libc_timeval {
    tv_sec: i64,
    tv_usec: i32,
}

extern "C" {
    #[link_name = "socket"]
    fn libc_socket(domain: i32, ty: i32, protocol: i32) -> i32;
    #[link_name = "sendto"]
    fn libc_sendto(
        fd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        addr: *const u8,
        addrlen: u32,
    ) -> isize;
    #[link_name = "recvfrom"]
    fn libc_recvfrom(
        fd: i32,
        buf: *mut u8,
        len: usize,
        flags: i32,
        addr: *mut u8,
        addrlen: *mut u32,
    ) -> isize;
    #[link_name = "setsockopt"]
    fn libc_setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i32;
}

// ============= PROTOCOL CONSTANTS =============

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;

const IP_ICMP: u8 = 1;
const IP_TCP: u8 = 6;
const IP_UDP: u8 = 17;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// ============= HELPER TYPES =============

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct TcpConnKey {
    guest_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
}

#[derive(Clone, Copy, PartialEq)]
enum TcpState {
    SynAckSent,
    Established,
    FinSent,
}

struct TcpConnection {
    stream: TcpStream,
    our_seq: u32,
    their_seq: u32,
    state: TcpState,
    /// Last sequence number acknowledged by the guest.
    acked_seq: u32,
    /// Receive window advertised by the guest (bytes).
    send_window: u32,
}

struct ConnectResult {
    key: TcpConnKey,
    result: std::io::Result<TcpStream>,
    guest_isn: u32,
}

struct PendingDns {
    guest_port: u16,
    guest_ip: [u8; 4],
}

// ============= MAIN STRUCT =============

pub struct UserNet {
    rx_queue: VecDeque<Vec<u8>>,
    tcp_conns: HashMap<TcpConnKey, TcpConnection>,
    pending_connects: HashSet<TcpConnKey>,
    connect_rx: mpsc::Receiver<ConnectResult>,
    connect_tx: mpsc::Sender<ConnectResult>,
    dns_socket: UdpSocket,
    pending_dns: HashMap<u16, PendingDns>,
    host_dns: SocketAddr,
    next_isn: u32,
    ip_id: u16,
    /// Sender to register new TCP socket fds with the NetPoller's kqueue.
    poller_fd_tx: Option<mpsc::Sender<RawFd>>,
    /// Write end of the NetPoller's wakeup pipe. The connect thread writes
    /// a byte here so the poller kicks the vcpu to process the new connection.
    poller_wakeup_fd: Option<RawFd>,
    /// Channel for receiving ICMP echo replies from proxy threads.
    icmp_rx: mpsc::Receiver<Vec<u8>>,
    icmp_tx: mpsc::Sender<Vec<u8>>,
}

// Safety: UserNet is only used from the VCPU thread.
// The mpsc channel handles cross-thread communication safely.
unsafe impl Send for UserNet {}

impl UserNet {
    pub fn new() -> Result<Self> {
        let dns_socket = UdpSocket::bind("0.0.0.0:0")?;
        dns_socket.set_nonblocking(true)?;

        let (connect_tx, connect_rx) = mpsc::channel();
        let (icmp_tx, icmp_rx) = mpsc::channel();
        let host_dns = get_host_dns();

        Ok(UserNet {
            rx_queue: VecDeque::new(),
            tcp_conns: HashMap::new(),
            pending_connects: HashSet::new(),
            connect_rx,
            connect_tx,
            dns_socket,
            pending_dns: HashMap::new(),
            host_dns,
            next_isn: 0x10000,
            ip_id: 1,
            poller_fd_tx: None,
            poller_wakeup_fd: None,
            icmp_rx,
            icmp_tx,
        })
    }

    pub fn mac_address(&self) -> [u8; 6] {
        GUEST_MAC
    }

    /// Create a `NetPoller` for this network backend's sockets.
    /// The DNS socket is registered immediately; TCP sockets are registered
    /// as connections are established.
    pub fn create_poller(&mut self, vcpu_id: u32) -> NetPoller {
        let poller = NetPoller::new(vcpu_id, self.dns_socket.as_raw_fd());
        self.poller_fd_tx = Some(poller.fd_sender());
        self.poller_wakeup_fd = Some(poller.wakeup_fd());
        poller
    }

    pub fn has_packets(&self) -> bool {
        !self.rx_queue.is_empty()
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> Option<usize> {
        let pkt = self.rx_queue.pop_front()?;
        let len = pkt.len().min(buf.len());
        buf[..len].copy_from_slice(&pkt[..len]);
        Some(len)
    }

    /// Process an outgoing Ethernet frame from the guest.
    pub fn write_packet(&mut self, eth_frame: &[u8]) -> Result<()> {
        if eth_frame.len() < 14 {
            return Ok(());
        }

        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
        let payload = &eth_frame[14..];

        match ethertype {
            ETH_ARP => self.handle_arp(payload),
            ETH_IPV4 => self.handle_ipv4(payload),
            _ => {} // Ignore unknown ethertypes
        }

        Ok(())
    }

    /// Poll host sockets for incoming data. Call this frequently from the VM loop.
    pub fn poll(&mut self) {
        self.poll_connects();
        self.poll_tcp_rx();
        self.poll_dns_rx();
        self.poll_icmp_rx();

        // If there is still data queued for the guest (e.g. poll_tcp_rx read
        // more data than process_rx could deliver in one batch), wake the
        // poller so it kicks the vcpu again on the next iteration.  Without
        // this, the kqueue may never fire again if the host socket was fully
        // drained, leaving queued packets stranded.
        if !self.rx_queue.is_empty() {
            if let Some(fd) = self.poller_wakeup_fd {
                let byte: u8 = 1;
                unsafe { kq::write(fd, &byte, 1) };
            }
        }
    }

    // ======== ARP ========

    fn handle_arp(&mut self, data: &[u8]) {
        if data.len() < 28 {
            return;
        }

        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        let hw_len = data[4];
        let proto_len = data[5];
        let opcode = u16::from_be_bytes([data[6], data[7]]);

        if hw_type != 1 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4 {
            return;
        }

        if opcode != 1 {
            return;
        } // Not a REQUEST

        let sender_mac: [u8; 6] = data[8..14].try_into().unwrap();
        let sender_ip: [u8; 4] = data[14..18].try_into().unwrap();
        let target_ip: [u8; 4] = data[24..28].try_into().unwrap();

        // Don't respond to ARP for guest's own IP
        if target_ip == GUEST_IP {
            return;
        }

        // Respond with gateway MAC for any other IP (proxy ARP)
        let reply = build_arp_reply(&target_ip, &sender_mac, &sender_ip);
        self.rx_queue.push_back(reply);
    }

    // ======== IPv4 ========

    fn handle_ipv4(&mut self, data: &[u8]) {
        if data.len() < 20 {
            return;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl {
            return;
        }

        let protocol = data[9];
        let src_ip: [u8; 4] = data[12..16].try_into().unwrap();
        let dst_ip: [u8; 4] = data[16..20].try_into().unwrap();
        let payload = &data[ihl..];

        match protocol {
            IP_TCP => self.handle_tcp(src_ip, dst_ip, payload),
            IP_UDP => self.handle_udp(src_ip, dst_ip, payload),
            IP_ICMP => self.handle_icmp(src_ip, dst_ip, payload),
            _ => {}
        }
    }

    // ======== ICMP ========

    fn handle_icmp(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        if data[0] != 8 || data[1] != 0 {
            return;
        } // Not Echo Request

        if dst_ip == GATEWAY_IP || dst_ip == DNS_IP {
            // Pings to our virtual IPs — reply locally.
            let mut reply = data.to_vec();
            reply[0] = 0; // Type: Echo Reply
            reply[2] = 0;
            reply[3] = 0; // Clear checksum
            let cksum = internet_checksum(&reply);
            reply[2] = (cksum >> 8) as u8;
            reply[3] = (cksum & 0xFF) as u8;

            let ip = build_ipv4_packet(dst_ip, src_ip, IP_ICMP, &reply, &mut self.ip_id);
            let frame = build_eth_frame(&GUEST_MAC, &GATEWAY_MAC, ETH_IPV4, &ip);
            self.rx_queue.push_back(frame);
        } else {
            // Pings to external IPs — proxy via a raw DGRAM socket.
            // macOS allows IPPROTO_ICMP DGRAM sockets without root (the kernel
            // rewrites the ICMP identifier, similar to Linux ping_group_range).
            let icmp_data = data.to_vec();
            let dst = dst_ip;
            let mut ip_id = self.ip_id;
            let tx: mpsc::Sender<Vec<u8>> = self.icmp_tx.clone();
            let wakeup_fd = self.poller_wakeup_fd;
            std::thread::spawn(move || {
                Self::proxy_icmp_echo(dst, &icmp_data, &tx, &mut ip_id);
                // Wake the poller so the vcpu processes the reply promptly.
                if let Some(fd) = wakeup_fd {
                    let byte: u8 = 1;
                    unsafe { kq::write(fd, &byte, 1) };
                }
            });
        }
    }

    /// Send an ICMP echo request to a real host and relay the reply back.
    fn proxy_icmp_echo(dst_ip: [u8; 4], data: &[u8], tx: &mpsc::Sender<Vec<u8>>, ip_id: &mut u16) {
        // Create a non-privileged ICMP socket (macOS SOCK_DGRAM + IPPROTO_ICMP).
        let sock = unsafe {
            let fd = libc_socket(ICMP_AF_INET, ICMP_SOCK_DGRAM, ICMP_IPPROTO_ICMP);
            if fd < 0 {
                return;
            }
            fd
        };

        // Build the ICMP echo request payload. macOS kernel rewrites the
        // identifier field, so we send the original data as-is.
        let addr = libc_sockaddr_in {
            sin_len: std::mem::size_of::<libc_sockaddr_in>() as u8,
            sin_family: ICMP_AF_INET as u8,
            sin_port: 0,
            sin_addr: u32::from_be_bytes(dst_ip).to_be(),
            sin_zero: [0; 8],
        };

        unsafe {
            // Set a 3-second receive timeout.
            let tv = libc_timeval {
                tv_sec: 3,
                tv_usec: 0,
            };
            libc_setsockopt(
                sock,
                ICMP_SOL_SOCKET,
                ICMP_SO_RCVTIMEO,
                &tv as *const _ as *const u8,
                std::mem::size_of::<libc_timeval>() as u32,
            );

            // Send the echo request.
            libc_sendto(
                sock,
                data.as_ptr(),
                data.len(),
                0,
                &addr as *const _ as *const u8,
                std::mem::size_of::<libc_sockaddr_in>() as u32,
            );

            // Receive the echo reply.
            let mut buf = [0u8; 2048];
            let n = libc_recvfrom(
                sock,
                buf.as_mut_ptr(),
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            kq::close(sock);

            if n <= 0 {
                return;
            }

            let received = &buf[..n as usize];

            // macOS returns the full IP+ICMP packet for SOCK_DGRAM ICMP
            // sockets. Strip the IP header to get the ICMP payload.
            let icmp_payload = if received.len() >= 20 && (received[0] >> 4) == 4 {
                let ihl = ((received[0] & 0x0F) as usize) * 4;
                if received.len() <= ihl {
                    return;
                }
                &received[ihl..]
            } else {
                received
            };

            let ip = build_ipv4_packet(dst_ip, GUEST_IP, IP_ICMP, icmp_payload, ip_id);
            let frame = build_eth_frame(&GUEST_MAC, &GATEWAY_MAC, ETH_IPV4, &ip);
            tx.send(frame).ok();
        }
    }

    /// Drain ICMP echo replies from proxy threads and queue them for the guest.
    fn poll_icmp_rx(&mut self) {
        while let Ok(frame) = self.icmp_rx.try_recv() {
            self.rx_queue.push_back(frame);
        }
    }

    // ======== UDP ========

    fn handle_udp(&mut self, src_ip: [u8; 4], _dst_ip: [u8; 4], data: &[u8]) {
        if data.len() < 8 {
            return;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let udp_len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < udp_len {
            return;
        }
        let payload = &data[8..udp_len.min(data.len())];

        if dst_port == 67 {
            // DHCP
            self.handle_dhcp(payload);
        } else if dst_port == 53 {
            // DNS
            self.handle_dns(src_port, src_ip, payload);
        }
    }

    // ======== DHCP ========

    fn handle_dhcp(&mut self, data: &[u8]) {
        if data.len() < 244 {
            return;
        }

        let op = data[0];
        if op != 1 {
            return;
        } // Not a BOOTREQUEST

        // Verify magic cookie
        if data[236..240] != [99, 130, 83, 99] {
            return;
        }

        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let chaddr: [u8; 6] = data[28..34].try_into().unwrap();

        let options = &data[240..];
        let msg_type = parse_dhcp_msg_type(options);

        match msg_type {
            Some(1) => {
                // DISCOVER → send OFFER
                let reply = self.build_dhcp_reply(2, xid, &chaddr);
                self.rx_queue.push_back(reply);
            }
            Some(3) => {
                // REQUEST → send ACK
                let reply = self.build_dhcp_reply(5, xid, &chaddr);
                self.rx_queue.push_back(reply);
            }
            _ => {}
        }
    }

    fn build_dhcp_reply(&mut self, msg_type: u8, xid: u32, chaddr: &[u8; 6]) -> Vec<u8> {
        let mut dhcp = vec![0u8; 300];

        dhcp[0] = 2; // op: BOOTREPLY
        dhcp[1] = 1; // htype: Ethernet
        dhcp[2] = 6; // hlen
        dhcp[4..8].copy_from_slice(&xid.to_be_bytes());
        dhcp[16..20].copy_from_slice(&GUEST_IP); // yiaddr
        dhcp[20..24].copy_from_slice(&GATEWAY_IP); // siaddr
        dhcp[28..34].copy_from_slice(chaddr); // chaddr

        // DHCP magic cookie
        dhcp[236] = 99;
        dhcp[237] = 130;
        dhcp[238] = 83;
        dhcp[239] = 99;

        // DHCP options
        let mut p = 240;

        // 53: DHCP Message Type
        dhcp[p] = 53;
        dhcp[p + 1] = 1;
        dhcp[p + 2] = msg_type;
        p += 3;

        // 54: Server Identifier
        dhcp[p] = 54;
        dhcp[p + 1] = 4;
        dhcp[p + 2..p + 6].copy_from_slice(&GATEWAY_IP);
        p += 6;

        // 1: Subnet Mask
        dhcp[p] = 1;
        dhcp[p + 1] = 4;
        dhcp[p + 2..p + 6].copy_from_slice(&NETMASK);
        p += 6;

        // 3: Router
        dhcp[p] = 3;
        dhcp[p + 1] = 4;
        dhcp[p + 2..p + 6].copy_from_slice(&GATEWAY_IP);
        p += 6;

        // 6: DNS Server
        dhcp[p] = 6;
        dhcp[p + 1] = 4;
        dhcp[p + 2..p + 6].copy_from_slice(&DNS_IP);
        p += 6;

        // 51: Lease Time (1 day)
        dhcp[p] = 51;
        dhcp[p + 1] = 4;
        dhcp[p + 2..p + 6].copy_from_slice(&86400u32.to_be_bytes());
        p += 6;

        // 255: End
        dhcp[p] = 255;
        p += 1;

        dhcp.truncate(p);

        // Wrap in UDP/IP/Ethernet (broadcast)
        let udp = build_udp(67, 68, &dhcp);
        let ip = build_ipv4_packet(
            GATEWAY_IP,
            [255, 255, 255, 255],
            IP_UDP,
            &udp,
            &mut self.ip_id,
        );
        build_eth_frame(&[0xFF; 6], &GATEWAY_MAC, ETH_IPV4, &ip)
    }

    // ======== DNS ========

    fn handle_dns(&mut self, src_port: u16, src_ip: [u8; 4], payload: &[u8]) {
        if payload.len() < 12 {
            return;
        }

        let dns_id = u16::from_be_bytes([payload[0], payload[1]]);

        // Forward DNS query to host DNS server
        if self.dns_socket.send_to(payload, self.host_dns).is_ok() {
            self.pending_dns.insert(
                dns_id,
                PendingDns {
                    guest_port: src_port,
                    guest_ip: src_ip,
                },
            );
        }
    }

    fn poll_dns_rx(&mut self) {
        let mut buf = [0u8; 2048];
        while let Ok((len, _addr)) = self.dns_socket.recv_from(&mut buf) {
            if len < 2 {
                continue;
            }
            let dns_id = u16::from_be_bytes([buf[0], buf[1]]);

            if let Some(pending) = self.pending_dns.remove(&dns_id) {
                let dns_data = &buf[..len];
                let udp = build_udp(53, pending.guest_port, dns_data);
                let ip = build_ipv4_packet(DNS_IP, pending.guest_ip, IP_UDP, &udp, &mut self.ip_id);
                let frame = build_eth_frame(&GUEST_MAC, &GATEWAY_MAC, ETH_IPV4, &ip);
                self.rx_queue.push_back(frame);
            }
        }
    }

    // ======== TCP ========

    fn handle_tcp(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], data: &[u8]) {
        if data.len() < 20 {
            return;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = ((data[12] >> 4) as usize) * 4;
        let flags = data[13];
        let window = u16::from_be_bytes([data[14], data[15]]) as u32;

        let payload = if data_offset < data.len() {
            &data[data_offset..]
        } else {
            &[]
        };

        let key = TcpConnKey {
            guest_port: src_port,
            dst_ip,
            dst_port,
        };

        // SYN — new connection
        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
            self.handle_tcp_syn(key, seq, dst_ip, dst_port);
            return;
        }

        // RST — close connection
        if flags & TCP_RST != 0 {
            self.tcp_conns.remove(&key);
            return;
        }

        // Remove connection temporarily (avoids borrow conflicts)
        let mut conn = match self.tcp_conns.remove(&key) {
            Some(c) => c,
            None => {
                // Unknown connection — send RST
                let rst = make_tcp_packet(
                    dst_ip,
                    dst_port,
                    src_ip,
                    src_port,
                    ack_num,
                    seq.wrapping_add(payload.len() as u32)
                        .wrapping_add(if flags & TCP_SYN != 0 { 1 } else { 0 }),
                    TCP_RST | TCP_ACK,
                    &[],
                    &[],
                    &mut self.ip_id,
                );
                self.rx_queue.push_back(rst);
                return;
            }
        };

        // ACK to our SYN-ACK → connection established
        if conn.state == TcpState::SynAckSent && flags & TCP_ACK != 0 {
            conn.state = TcpState::Established;
        }

        // Update flow control from every ACK the guest sends.
        if flags & TCP_ACK != 0 {
            conn.acked_seq = ack_num;
            conn.send_window = window;
        }

        // Data from guest → write to host socket, send ACK
        if !payload.is_empty() && conn.state == TcpState::Established {
            if seq == conn.their_seq {
                let _ = conn.stream.write_all(payload);
                conn.their_seq = conn.their_seq.wrapping_add(payload.len() as u32);
            }
            // Always ACK (handles retransmits)
            let ack_pkt = make_tcp_packet(
                dst_ip,
                dst_port,
                src_ip,
                src_port,
                conn.our_seq,
                conn.their_seq,
                TCP_ACK,
                &[],
                &[],
                &mut self.ip_id,
            );
            self.rx_queue.push_back(ack_pkt);
        }

        // FIN from guest → ACK + FIN, close connection
        if flags & TCP_FIN != 0 {
            conn.their_seq = conn.their_seq.wrapping_add(1);
            let fin_ack = make_tcp_packet(
                dst_ip,
                dst_port,
                src_ip,
                src_port,
                conn.our_seq,
                conn.their_seq,
                TCP_ACK | TCP_FIN,
                &[],
                &[],
                &mut self.ip_id,
            );
            self.rx_queue.push_back(fin_ack);
            conn.our_seq = conn.our_seq.wrapping_add(1);
            conn.stream.shutdown(std::net::Shutdown::Both).ok();
            conn.state = TcpState::FinSent;
        }

        // Put connection back (unless it's done)
        if conn.state != TcpState::FinSent {
            self.tcp_conns.insert(key, conn);
        }
    }

    fn handle_tcp_syn(&mut self, key: TcpConnKey, guest_isn: u32, dst_ip: [u8; 4], dst_port: u16) {
        // Don't start duplicate connections
        if self.tcp_conns.contains_key(&key) || self.pending_connects.contains(&key) {
            return;
        }

        self.pending_connects.insert(key.clone());

        // Spawn a thread to connect (non-blocking from the VM loop's perspective)
        let tx = self.connect_tx.clone();
        let wakeup_fd = self.poller_wakeup_fd;
        // Map the virtual gateway IP (10.0.2.2) to localhost so the guest
        // can reach host-local services (e.g. HTTP proxies).
        let host_ip = if dst_ip == GATEWAY_IP {
            Ipv4Addr::LOCALHOST
        } else {
            Ipv4Addr::new(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3])
        };
        let dst_addr = SocketAddr::new(IpAddr::V4(host_ip), dst_port);
        let key_clone = key.clone();

        std::thread::spawn(move || {
            let result = TcpStream::connect_timeout(&dst_addr, std::time::Duration::from_secs(10));
            if let Ok(ref stream) = result {
                stream.set_nonblocking(true).ok();
                stream.set_nodelay(true).ok();
            }
            tx.send(ConnectResult {
                key: key_clone,
                result,
                guest_isn,
            })
            .ok();
            // Wake the poller so it kicks the vcpu to process this connection.
            if let Some(fd) = wakeup_fd {
                let byte: u8 = 1;
                unsafe { kq::write(fd, &byte, 1) };
            }
        });
    }

    fn poll_connects(&mut self) {
        while let Ok(cr) = self.connect_rx.try_recv() {
            self.pending_connects.remove(&cr.key);

            match cr.result {
                Ok(stream) => {
                    let our_isn = self.next_isn;
                    self.next_isn = self.next_isn.wrapping_add(64000);

                    let their_seq = cr.guest_isn.wrapping_add(1);

                    // Register the new socket with the kqueue poller so it
                    // wakes the vcpu when data arrives from the remote host.
                    if let Some(ref tx) = self.poller_fd_tx {
                        tx.send(stream.as_raw_fd()).ok();
                        // Wake the poller so it picks up the fd from the channel
                        // and registers it with kqueue before blocking again.
                        if let Some(fd) = self.poller_wakeup_fd {
                            let byte: u8 = 1;
                            unsafe { kq::write(fd, &byte, 1) };
                        }
                    }

                    let initial_seq = our_isn.wrapping_add(1);
                    let conn = TcpConnection {
                        stream,
                        our_seq: initial_seq, // After SYN-ACK
                        their_seq,
                        state: TcpState::SynAckSent,
                        acked_seq: initial_seq,
                        send_window: 65535,
                    };

                    // Build SYN-ACK with MSS option
                    let mss_option = [2, 4, (TCP_MSS >> 8) as u8, (TCP_MSS & 0xFF) as u8];
                    let syn_ack = make_tcp_packet(
                        cr.key.dst_ip,
                        cr.key.dst_port,
                        GUEST_IP,
                        cr.key.guest_port,
                        our_isn,
                        their_seq,
                        TCP_SYN | TCP_ACK,
                        &[],
                        &mss_option,
                        &mut self.ip_id,
                    );
                    self.rx_queue.push_back(syn_ack);
                    self.tcp_conns.insert(cr.key, conn);
                }
                Err(_) => {
                    // Connection failed — send RST
                    let rst = make_tcp_packet(
                        cr.key.dst_ip,
                        cr.key.dst_port,
                        GUEST_IP,
                        cr.key.guest_port,
                        0,
                        cr.guest_isn.wrapping_add(1),
                        TCP_RST | TCP_ACK,
                        &[],
                        &[],
                        &mut self.ip_id,
                    );
                    self.rx_queue.push_back(rst);
                }
            }
        }
    }

    fn poll_tcp_rx(&mut self) {
        let keys: Vec<_> = self.tcp_conns.keys().cloned().collect();

        for key in keys {
            let mut conn = match self.tcp_conns.remove(&key) {
                Some(c) => c,
                None => continue,
            };

            if conn.state == TcpState::FinSent {
                // Connection is done — don't put back
                continue;
            }

            if conn.state != TcpState::Established {
                self.tcp_conns.insert(key, conn);
                continue;
            }

            let mut should_keep = true;

            // Read available segments, respecting the guest's receive window.
            // We stop sending when the amount of unacknowledged (in-flight) data
            // reaches the window the guest last advertised.  Non-blocking sockets
            // return WouldBlock when drained.
            loop {
                let in_flight = conn.our_seq.wrapping_sub(conn.acked_seq);
                if in_flight >= conn.send_window {
                    break; // Window full — wait for guest ACKs
                }

                let max_read = (conn.send_window - in_flight).min(TCP_MSS as u32) as usize;
                let mut buf = [0u8; TCP_MSS];
                match conn.stream.read(&mut buf[..max_read]) {
                    Ok(0) => {
                        // EOF — send FIN
                        let pkt = make_tcp_packet(
                            key.dst_ip,
                            key.dst_port,
                            GUEST_IP,
                            key.guest_port,
                            conn.our_seq,
                            conn.their_seq,
                            TCP_FIN | TCP_ACK,
                            &[],
                            &[],
                            &mut self.ip_id,
                        );
                        self.rx_queue.push_back(pkt);
                        conn.our_seq = conn.our_seq.wrapping_add(1);
                        conn.state = TcpState::FinSent;
                        should_keep = false;
                        break;
                    }
                    Ok(n) => {
                        let pkt = make_tcp_packet(
                            key.dst_ip,
                            key.dst_port,
                            GUEST_IP,
                            key.guest_port,
                            conn.our_seq,
                            conn.their_seq,
                            TCP_PSH | TCP_ACK,
                            &buf[..n],
                            &[],
                            &mut self.ip_id,
                        );
                        self.rx_queue.push_back(pkt);
                        conn.our_seq = conn.our_seq.wrapping_add(n as u32);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break; // No more data
                    }
                    Err(_) => {
                        // Error — send RST
                        let pkt = make_tcp_packet(
                            key.dst_ip,
                            key.dst_port,
                            GUEST_IP,
                            key.guest_port,
                            conn.our_seq,
                            conn.their_seq,
                            TCP_RST | TCP_ACK,
                            &[],
                            &[],
                            &mut self.ip_id,
                        );
                        self.rx_queue.push_back(pkt);
                        should_keep = false;
                        break;
                    }
                }
            }

            if should_keep {
                self.tcp_conns.insert(key, conn);
            }
        }
    }
}

impl Drop for UserNet {
    fn drop(&mut self) {
        // Signal the NetPoller thread to shut down so it can be joined.
        if let Some(fd) = self.poller_wakeup_fd.take() {
            signal_poller_shutdown(fd);
        }
    }
}

// ============= PACKET BUILDING (free functions) =============

/// Internet checksum (RFC 1071): ones-complement sum of 16-bit words.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn build_eth_frame(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn build_ipv4_packet(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    payload: &[u8],
    ip_id: &mut u16,
) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let id = *ip_id;
    *ip_id = ip_id.wrapping_add(1);

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // Version 4, IHL 5
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = (total_len & 0xFF) as u8;
    pkt[4] = (id >> 8) as u8;
    pkt[5] = (id & 0xFF) as u8;
    pkt[6] = 0x40; // Don't Fragment
    pkt[8] = 64; // TTL
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);

    // Header checksum
    let cksum = internet_checksum(&pkt[..20]);
    pkt[10] = (cksum >> 8) as u8;
    pkt[11] = (cksum & 0xFF) as u8;

    pkt[20..].copy_from_slice(payload);
    pkt
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let options_padded_len = (options.len() + 3) & !3;
    let header_len = 20 + options_padded_len;
    let data_offset = (header_len / 4) as u8;

    let mut seg = vec![0u8; header_len + payload.len()];
    seg[0..2].copy_from_slice(&src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    seg[12] = data_offset << 4;
    seg[13] = flags;
    seg[14..16].copy_from_slice(&window.to_be_bytes());
    // checksum at [16..18] computed later
    // urgent ptr at [18..20] is 0

    if !options.is_empty() {
        seg[20..20 + options.len()].copy_from_slice(options);
    }
    if !payload.is_empty() {
        seg[header_len..].copy_from_slice(payload);
    }

    seg
}

fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let tcp_len = tcp_segment.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(IP_TCP);
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}

/// Build a complete Ethernet frame containing a TCP segment.
#[allow(clippy::too_many_arguments)]
fn make_tcp_packet(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    options: &[u8],
    ip_id: &mut u16,
) -> Vec<u8> {
    let mut tcp_seg =
        build_tcp_segment(src_port, dst_port, seq, ack, flags, 65535, payload, options);

    // Compute TCP checksum
    let cksum = tcp_checksum(src_ip, dst_ip, &tcp_seg);
    tcp_seg[16] = (cksum >> 8) as u8;
    tcp_seg[17] = (cksum & 0xFF) as u8;

    let ip = build_ipv4_packet(src_ip, dst_ip, IP_TCP, &tcp_seg, ip_id);
    build_eth_frame(&GUEST_MAC, &GATEWAY_MAC, ETH_IPV4, &ip)
}

fn build_arp_reply(target_ip: &[u8; 4], sender_mac: &[u8; 6], sender_ip: &[u8; 4]) -> Vec<u8> {
    let mut arp = vec![0u8; 28];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // HW type: Ethernet
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // Proto type: IPv4
    arp[4] = 6; // HW len
    arp[5] = 4; // Proto len
    arp[6..8].copy_from_slice(&2u16.to_be_bytes()); // Opcode: Reply
    arp[8..14].copy_from_slice(&GATEWAY_MAC); // Sender MAC
    arp[14..18].copy_from_slice(target_ip); // Sender IP (the resolved IP)
    arp[18..24].copy_from_slice(sender_mac); // Target MAC (original requester)
    arp[24..28].copy_from_slice(sender_ip); // Target IP

    build_eth_frame(sender_mac, &GATEWAY_MAC, ETH_ARP, &arp)
}

fn build_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // checksum = 0 (optional for UDP over IPv4)
    udp[8..].copy_from_slice(payload);
    udp
}

/// Parse DHCP option 53 (message type) from the options section.
fn parse_dhcp_msg_type(options: &[u8]) -> Option<u8> {
    let mut pos = 0;
    loop {
        if pos >= options.len() {
            return None;
        }
        let opt = options[pos];
        if opt == 255 {
            return None;
        } // End
        if opt == 0 {
            pos += 1;
            continue;
        } // Pad
        if pos + 1 >= options.len() {
            return None;
        }
        let len = options[pos + 1] as usize;
        if opt == 53 && len == 1 && pos + 2 < options.len() {
            return Some(options[pos + 2]);
        }
        pos += 2 + len;
    }
}

/// Get the host's DNS server from /etc/resolv.conf.
fn get_host_dns() -> SocketAddr {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver") {
                if let Some(ip_str) = line.split_whitespace().nth(1) {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        return SocketAddr::new(IpAddr::V4(ip), 53);
                    }
                }
            }
        }
    }
    // Fallback to Google DNS
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
}

// ============= EVENT-DRIVEN NETWORK POLLER =============

/// kqueue-based I/O poller that monitors host-side sockets and kicks the
/// vcpu (via `hv_vcpus_exit`) only when data actually arrives.
///
/// This replaces a fixed-interval timer thread, giving zero idle CPU usage
/// and sub-microsecond wakeup latency.
pub struct NetPoller {
    kq: RawFd,
    wakeup_read: RawFd,
    wakeup_write: RawFd,
    vcpu_id: u32,
    fd_rx: mpsc::Receiver<RawFd>,
    fd_tx: mpsc::Sender<RawFd>,
}

// kqueue / kevent FFI — just the handful of definitions we need.
mod kq {
    use std::os::fd::RawFd;

    pub const EVFILT_READ: i16 = -1;
    pub const EV_ADD: u16 = 0x0001;
    pub const EV_ENABLE: u16 = 0x0004;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Kevent {
        pub ident: usize,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: isize,
        pub udata: *mut std::ffi::c_void,
    }

    // Safety: Kevent contains a raw pointer field (udata) which we always
    // set to null and never dereference, making it safe to send.
    unsafe impl Send for Kevent {}

    // We always pass null for the timeout (block forever), so we just
    // declare it as *const std::ffi::c_void to avoid a libc dependency.
    extern "C" {
        pub fn kqueue() -> RawFd;
        pub fn kevent(
            kq: RawFd,
            changelist: *const Kevent,
            nchanges: i32,
            eventlist: *mut Kevent,
            nevents: i32,
            timeout: *const std::ffi::c_void,
        ) -> i32;
        pub fn pipe(fds: *mut [RawFd; 2]) -> i32;
        pub fn close(fd: RawFd) -> i32;
        pub fn read(fd: RawFd, buf: *mut u8, count: usize) -> isize;
        pub fn write(fd: RawFd, buf: *const u8, count: usize) -> isize;
    }

    /// Register a file descriptor for EVFILT_READ on the given kqueue.
    pub fn register_fd(kq: RawFd, fd: RawFd) {
        let change = Kevent {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags: EV_ADD | EV_ENABLE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        unsafe {
            kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
        }
    }
}

impl NetPoller {
    /// Create a new poller. `dns_fd` is the DNS UDP socket's raw fd, which
    /// is registered immediately so DNS replies wake the vcpu.
    pub fn new(vcpu_id: u32, dns_fd: RawFd) -> Self {
        let kq = unsafe { kq::kqueue() };
        assert!(kq >= 0, "kqueue() failed");

        let mut pipe_fds: [RawFd; 2] = [0; 2];
        let ret = unsafe { kq::pipe(&mut pipe_fds) };
        assert!(ret == 0, "pipe() failed");

        let wakeup_read = pipe_fds[0];
        let wakeup_write = pipe_fds[1];

        // Register the wakeup pipe and DNS socket with kqueue.
        kq::register_fd(kq, wakeup_read);
        kq::register_fd(kq, dns_fd);

        let (fd_tx, fd_rx) = mpsc::channel();

        NetPoller {
            kq,
            wakeup_read,
            wakeup_write,
            vcpu_id,
            fd_rx,
            fd_tx,
        }
    }

    /// Get a sender handle that can be used to register new socket fds
    /// with the poller from the VM thread.
    pub fn fd_sender(&self) -> mpsc::Sender<RawFd> {
        self.fd_tx.clone()
    }

    /// Get the write end of the wakeup pipe (used to signal shutdown).
    pub fn wakeup_fd(&self) -> RawFd {
        self.wakeup_write
    }

    /// Blocking event loop — run this on a dedicated thread.
    /// Blocks on kevent() until a monitored socket becomes readable,
    /// then kicks the vcpu. Exits when a byte is read from the wakeup pipe.
    pub fn run(self) {
        use crate::hypervisor::Vcpu;

        let mut events: [kq::Kevent; 32] = [kq::Kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        }; 32];

        loop {
            // Before blocking, register any newly-established TCP sockets
            // that the VM thread sent us.
            while let Ok(fd) = self.fd_rx.try_recv() {
                kq::register_fd(self.kq, fd);
            }

            let n = unsafe {
                kq::kevent(
                    self.kq,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    std::ptr::null(), // block indefinitely
                )
            };

            if n <= 0 {
                continue; // spurious wakeup or EINTR
            }

            // Check if the wakeup pipe fired.
            let mut shutdown = false;
            for ev in &events[..n as usize] {
                if ev.ident == self.wakeup_read as usize {
                    // Drain the pipe and check for the shutdown sentinel (0xFF).
                    let mut buf = [0u8; 64];
                    let nread = unsafe { kq::read(self.wakeup_read, buf.as_mut_ptr(), buf.len()) };
                    if nread > 0 && buf[..nread as usize].contains(&0xFF) {
                        shutdown = true;
                    }
                    // Non-shutdown wakeups (e.g. new fd to register) just
                    // cause us to loop back and pick up the fd from fd_rx.
                }
            }

            if shutdown {
                break;
            }

            // A host socket has data — kick the vcpu so the VM loop polls.
            Vcpu::force_exit(&[self.vcpu_id]).ok();
        }

        // Cleanup
        unsafe {
            kq::close(self.kq);
            kq::close(self.wakeup_read);
            kq::close(self.wakeup_write);
        }
    }
}

/// Signals the NetPoller to shut down by writing to the wakeup pipe.
/// This is called when UserNet is dropped (i.e. VM shutdown).
fn signal_poller_shutdown(wakeup_fd: RawFd) {
    let byte: u8 = 0xFF;
    unsafe { kq::write(wakeup_fd, &byte, 1) };
}

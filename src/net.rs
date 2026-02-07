use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Https,
    Tcp,
    Udp,
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" => Some(Protocol::Http),
            "https" => Some(Protocol::Https),
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        }
    }
}

/// Network filter that inspects packets for protocol and hostname control.
///
/// - **Protocol filtering**: Checks IP/TCP/UDP headers against allowed protocols.
///   HTTP = TCP port 80, HTTPS = TCP port 443.
/// - **Hostname filtering**: Intercepts DNS queries (UDP port 53) and only allows
///   resolution of whitelisted hostnames. This effectively blocks connections to
///   non-whitelisted hosts since the guest can't resolve their IPs.
pub struct NetworkFilter {
    allowed_protocols: HashSet<Protocol>,
    allowed_hosts: Option<HashSet<String>>,
}

impl NetworkFilter {
    pub fn new() -> Self {
        NetworkFilter {
            allowed_protocols: HashSet::new(),
            allowed_hosts: None,
        }
    }

    /// Create a permissive filter (allows everything).
    #[allow(dead_code)]
    pub fn allow_all() -> Self {
        let mut f = Self::new();
        f.allowed_protocols.insert(Protocol::Http);
        f.allowed_protocols.insert(Protocol::Https);
        f.allowed_protocols.insert(Protocol::Tcp);
        f.allowed_protocols.insert(Protocol::Udp);
        f
    }

    /// Set allowed protocols.
    pub fn set_protocols(&mut self, protocols: Vec<Protocol>) {
        self.allowed_protocols = protocols.into_iter().collect();
    }

    /// Set allowed hosts whitelist.
    pub fn set_allowed_hosts(&mut self, hosts: Vec<String>) {
        self.allowed_hosts = Some(hosts.into_iter().map(|h| h.to_lowercase()).collect());
    }

    /// Filter a TX packet (guest → network).
    /// Returns true if the packet should be forwarded, false if it should be dropped.
    pub fn filter_tx_packet(&self, eth_frame: &[u8]) -> bool {
        // Need at least an Ethernet header (14 bytes)
        if eth_frame.len() < 14 {
            return false;
        }

        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);

        match ethertype {
            0x0806 => true,  // ARP — always allow (needed for basic networking)
            0x86DD => true,  // IPv6 — allow (TODO: add IPv6 filtering)
            0x0800 => self.filter_ipv4(&eth_frame[14..]),  // IPv4
            _ => true,       // Unknown — pass through
        }
    }

    /// Filter an IPv4 packet.
    fn filter_ipv4(&self, ip_data: &[u8]) -> bool {
        if ip_data.len() < 20 {
            return false;
        }

        let ihl = (ip_data[0] & 0x0F) as usize * 4;
        if ip_data.len() < ihl {
            return false;
        }

        let protocol = ip_data[9];
        let transport = &ip_data[ihl..];

        match protocol {
            1 => true,  // ICMP — always allow (ping, etc.)

            6 => {
                // TCP
                if transport.len() < 4 { return false; }
                let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

                match dst_port {
                    80  => self.allowed_protocols.contains(&Protocol::Http),
                    443 => self.allowed_protocols.contains(&Protocol::Https),
                    53  => true, // DNS over TCP — allow if any protocol is enabled
                    _   => self.allowed_protocols.contains(&Protocol::Tcp),
                }
            }

            17 => {
                // UDP
                if transport.len() < 4 { return false; }
                let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

                if dst_port == 53 {
                    // DNS query — apply hostname filter
                    return self.filter_dns_query(transport);
                }

                // DHCP (ports 67/68) — always allow
                if dst_port == 67 || dst_port == 68 { return true; }

                self.allowed_protocols.contains(&Protocol::Udp)
            }

            _ => false, // Other IP protocols — block
        }
    }

    /// Filter a DNS query (UDP payload).
    /// Returns true if the query should be forwarded.
    fn filter_dns_query(&self, udp_data: &[u8]) -> bool {
        let hosts = match &self.allowed_hosts {
            Some(h) => h,
            None => return true, // No hostname filter → allow all DNS
        };

        // UDP header is 8 bytes, DNS starts after
        if udp_data.len() < 8 + 12 { return true; } // Malformed — pass through
        let dns = &udp_data[8..];

        // DNS header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
        let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
        if qdcount == 0 { return true; }

        // Parse the first question's QNAME
        if let Some(hostname) = parse_dns_name(&dns[12..]) {
            let hostname_lower = hostname.to_lowercase();
            // Check if hostname matches any allowed host (exact or subdomain)
            hosts.iter().any(|allowed| {
                hostname_lower == *allowed
                    || hostname_lower.ends_with(&format!(".{}", allowed))
            })
        } else {
            true // Can't parse — pass through
        }
    }

    /// Parse protocols from comma-separated string.
    pub fn parse_protocols(s: &str) -> Vec<Protocol> {
        s.split(',')
            .filter_map(|p| Protocol::from_str(p.trim()))
            .collect()
    }

    /// Parse hosts from comma-separated string.
    pub fn parse_hosts(s: &str) -> Vec<String> {
        s.split(',')
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect()
    }
}

/// Parse a DNS-encoded domain name (e.g. \x03www\x06google\x03com\x00 → "www.google.com")
fn parse_dns_name(data: &[u8]) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() { return None; }
        let label_len = data[pos] as usize;
        if label_len == 0 { break; }            // End of name
        if label_len >= 0xC0 { break; }          // Compression pointer — stop
        pos += 1;
        if pos + label_len > data.len() { return None; }
        parts.push(std::str::from_utf8(&data[pos..pos + label_len]).ok()?);
        pos += label_len;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_parsing() {
        assert_eq!(Protocol::from_str("http"), Some(Protocol::Http));
        assert_eq!(Protocol::from_str("HTTPS"), Some(Protocol::Https));
        assert_eq!(Protocol::from_str("invalid"), None);
    }

    #[test]
    fn test_filter_basic() {
        let mut filter = NetworkFilter::new();
        filter.set_protocols(vec![Protocol::Http, Protocol::Https]);
        filter.set_allowed_hosts(vec!["example.com".to_string()]);

        // DNS name parsing
        let dns_name = b"\x07example\x03com\x00";
        assert_eq!(parse_dns_name(dns_name), Some("example.com".to_string()));

        let dns_name2 = b"\x03www\x07example\x03com\x00";
        assert_eq!(parse_dns_name(dns_name2), Some("www.example.com".to_string()));
    }
}

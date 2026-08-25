use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportInfo {
    pub kind: Transport,
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Clone, Debug)]
pub struct DecodedPacket {
    pub source: String,
    pub destination: String,
    pub source_addresses: Vec<String>,
    pub destination_addresses: Vec<String>,
    pub address_associations: Vec<Vec<String>>,
    pub transport: Option<TransportInfo>,
    pub application: String,
    pub summary: String,
}

pub fn decode_packet(link_type: u16, packet: &[u8]) -> Option<DecodedPacket> {
    match link_type {
        1 => decode_ethernet(packet),
        101 => decode_ip(packet, None, None),
        _ => None,
    }
}

fn decode_ethernet(packet: &[u8]) -> Option<DecodedPacket> {
    if packet.len() < 14 {
        return None;
    }
    let destination_mac = format_mac(&packet[0..6]);
    let source_mac = format_mac(&packet[6..12]);
    let mut ether_type = u16::from_be_bytes([packet[12], packet[13]]);
    let mut offset = 14;
    while matches!(ether_type, 0x8100 | 0x88a8) {
        if packet.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        offset += 4;
    }
    match ether_type {
        0x0806 => decode_arp(&packet[offset..], source_mac, destination_mac),
        0x0800 | 0x86dd => decode_ip(&packet[offset..], Some(source_mac), Some(destination_mac)),
        _ => Some(DecodedPacket {
            source: source_mac.clone(),
            destination: destination_mac.clone(),
            source_addresses: vec![source_mac],
            destination_addresses: vec![destination_mac],
            address_associations: Vec::new(),
            transport: None,
            application: format!("EtherType 0x{ether_type:04x}"),
            summary: format!("Ethernet protocol 0x{ether_type:04x}"),
        }),
    }
}

fn decode_arp(packet: &[u8], source_mac: String, destination_mac: String) -> Option<DecodedPacket> {
    if packet.len() < 8 {
        return None;
    }
    let hardware_len = packet[4] as usize;
    let protocol_len = packet[5] as usize;
    let operation = u16::from_be_bytes([packet[6], packet[7]]);
    let required = 8 + (hardware_len + protocol_len) * 2;
    if packet.len() < required {
        return None;
    }
    let sender_hardware = &packet[8..8 + hardware_len];
    let sender_protocol = &packet[8 + hardware_len..8 + hardware_len + protocol_len];
    let target_hardware_start = 8 + hardware_len + protocol_len;
    let target_hardware = &packet[target_hardware_start..target_hardware_start + hardware_len];
    let target_protocol = &packet[target_hardware_start + hardware_len..required];
    let sender_mac = if hardware_len == 6 {
        format_mac(sender_hardware)
    } else {
        source_mac
    };
    let target_mac = if hardware_len == 6 {
        format_mac(target_hardware)
    } else {
        destination_mac
    };
    let sender_ip = if protocol_len == 4 {
        format_ipv4(sender_protocol)
    } else {
        hex_address(sender_protocol)
    };
    let target_ip = if protocol_len == 4 {
        format_ipv4(target_protocol)
    } else {
        hex_address(target_protocol)
    };
    let operation_label = match operation {
        1 => "request",
        2 => "reply",
        _ => "operation",
    };
    let mut associations = vec![vec![sender_ip.clone(), sender_mac.clone()]];
    if target_hardware.iter().any(|byte| *byte != 0) {
        associations.push(vec![target_ip.clone(), target_mac.clone()]);
    }
    Some(DecodedPacket {
        source: sender_ip.clone(),
        destination: target_ip.clone(),
        source_addresses: vec![sender_ip.clone(), sender_mac],
        destination_addresses: vec![target_ip.clone(), target_mac],
        address_associations: associations,
        transport: None,
        application: "ARP".into(),
        summary: format!("ARP {operation_label}: {sender_ip} → {target_ip}"),
    })
}

fn decode_ip(
    packet: &[u8],
    source_mac: Option<String>,
    destination_mac: Option<String>,
) -> Option<DecodedPacket> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => decode_ipv4(packet, source_mac, destination_mac),
        Some(6) => decode_ipv6(packet, source_mac, destination_mac),
        _ => None,
    }
}

fn decode_ipv4(
    packet: &[u8],
    source_mac: Option<String>,
    destination_mac: Option<String>,
) -> Option<DecodedPacket> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = (packet[0] as usize & 0x0f) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if header_len < 20 || total_len < header_len || packet.len() < total_len {
        return None;
    }
    let source = format_ipv4(&packet[12..16]);
    let destination = format_ipv4(&packet[16..20]);
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return decode_fragment(
            "IPv4 fragment",
            source,
            destination,
            source_mac,
            destination_mac,
        );
    }
    decode_transport(
        packet[9],
        &packet[header_len..total_len],
        source,
        destination,
        source_mac,
        destination_mac,
    )
}

fn decode_ipv6(
    packet: &[u8],
    source_mac: Option<String>,
    destination_mac: Option<String>,
) -> Option<DecodedPacket> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = 40usize.checked_add(payload_len)?;
    if packet.len() < total_len {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).to_string();
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).to_string();
    let mut next_header = packet[6];
    let mut offset = 40;
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                if total_len < offset + 2 {
                    return None;
                }
                next_header = packet[offset];
                offset += (packet[offset + 1] as usize + 1) * 8;
            }
            44 => {
                if total_len < offset + 8 {
                    return None;
                }
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if fragment & 0xfff9 != 0 {
                    return decode_fragment(
                        "IPv6 fragment",
                        source,
                        destination,
                        source_mac,
                        destination_mac,
                    );
                }
                next_header = packet[offset];
                offset += 8;
            }
            _ => break,
        }
    }
    if offset > total_len {
        return None;
    }
    decode_transport(
        next_header,
        &packet[offset..total_len],
        source,
        destination,
        source_mac,
        destination_mac,
    )
}

fn decode_fragment(
    label: &str,
    source: String,
    destination: String,
    source_mac: Option<String>,
    destination_mac: Option<String>,
) -> Option<DecodedPacket> {
    let mut source_addresses = vec![source.clone()];
    let mut destination_addresses = vec![destination.clone()];
    if let Some(mac) = source_mac {
        source_addresses.push(mac);
    }
    if let Some(mac) = destination_mac {
        destination_addresses.push(mac);
    }
    Some(DecodedPacket {
        source,
        destination,
        source_addresses,
        destination_addresses,
        address_associations: Vec::new(),
        transport: None,
        application: label.to_owned(),
        summary: "Fragmented payload; transport decode deferred".to_owned(),
    })
}

fn decode_transport(
    protocol: u8,
    payload: &[u8],
    source: String,
    destination: String,
    source_mac: Option<String>,
    destination_mac: Option<String>,
) -> Option<DecodedPacket> {
    let mut source_addresses = vec![source.clone()];
    let mut destination_addresses = vec![destination.clone()];
    // L2 and L3 destinations can differ when a router is present. Keep the
    // observed MACs as addresses, but only ARP creates cross-layer identity
    // associations.
    if let Some(mac) = source_mac {
        source_addresses.push(mac);
    }
    if let Some(mac) = destination_mac {
        destination_addresses.push(mac);
    }
    let associations = Vec::new();

    let (transport, application, summary) = match protocol {
        6 => decode_tcp(payload)?,
        17 => decode_udp(payload)?,
        1 | 58 => (
            None,
            "ICMP".to_owned(),
            format!("ICMP {} bytes", payload.len()),
        ),
        value => (
            None,
            format!("IP/{value}"),
            format!("IP protocol {value}, {} bytes", payload.len()),
        ),
    };
    Some(DecodedPacket {
        source,
        destination,
        source_addresses,
        destination_addresses,
        address_associations: associations,
        transport,
        application,
        summary,
    })
}

fn decode_tcp(packet: &[u8]) -> Option<(Option<TransportInfo>, String, String)> {
    if packet.len() < 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    let header_len = ((packet[12] >> 4) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    let flags = packet[13];
    let payload = &packet[header_len..];
    let application = classify_tcp(source_port, destination_port, payload);
    let flag_names = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
    ]
    .into_iter()
    .filter_map(|(mask, name)| (flags & mask != 0).then_some(name))
    .collect::<Vec<_>>()
    .join(",");
    let summary = format!(
        "{source_port} → {destination_port} [{}] {} payload bytes",
        if flag_names.is_empty() {
            "—"
        } else {
            &flag_names
        },
        payload.len()
    );
    Some((
        Some(TransportInfo {
            kind: Transport::Tcp,
            source_port,
            destination_port,
        }),
        application,
        summary,
    ))
}

fn decode_udp(packet: &[u8]) -> Option<(Option<TransportInfo>, String, String)> {
    if packet.len() < 8 {
        return None;
    }
    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    let datagram_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if datagram_len < 8 || datagram_len > packet.len() {
        return None;
    }
    let application = match (source_port, destination_port) {
        (53, _) | (_, 53) => "DNS",
        (67 | 68, _) | (_, 67 | 68) => "DHCP",
        (443, _) | (_, 443) => "QUIC",
        (5353, _) | (_, 5353) => "mDNS",
        _ => "UDP",
    }
    .to_owned();
    Some((
        Some(TransportInfo {
            kind: Transport::Udp,
            source_port,
            destination_port,
        }),
        application,
        format!(
            "{source_port} → {destination_port}, {} payload bytes",
            datagram_len - 8
        ),
    ))
}

fn classify_tcp(source_port: u16, destination_port: u16, payload: &[u8]) -> String {
    const HTTP_METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    if payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return "HTTP/2".into();
    }
    if payload.starts_with(b"HTTP/1.")
        || HTTP_METHODS
            .iter()
            .any(|method| payload.starts_with(method))
    {
        return "HTTP/1".into();
    }
    match (source_port, destination_port) {
        (443, _) | (_, 443) => "TLS",
        (80 | 8000 | 8080, _) | (_, 80 | 8000 | 8080) => "HTTP/1",
        (22, _) | (_, 22) => "SSH",
        (53, _) | (_, 53) => "DNS/TCP",
        _ => "TCP",
    }
    .into()
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("-")
}

fn format_ipv4(bytes: &[u8]) -> String {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
}

fn hex_address(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(total_len: u16, fragment: u16, trailing: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            0,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            6,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
            0x04,
            0xd2,
            0,
            80,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0x50,
            0x02,
            0xff,
            0xff,
            0,
            0,
            0,
            0,
        ];
        packet.extend_from_slice(trailing);
        packet
    }

    #[test]
    fn ipv4_total_length_excludes_ethernet_padding() {
        let packet = ipv4_tcp(40, 0, b"GET / HTTP/1.1\r\n\r\n");
        let decoded = decode_ip(&packet, None, None).unwrap();
        assert_eq!(decoded.application, "HTTP/1");
        assert!(decoded.summary.ends_with("0 payload bytes"));
    }

    #[test]
    fn rejects_truncated_ipv4_total_length() {
        let packet = ipv4_tcp(80, 0, &[]);
        assert!(decode_ip(&packet, None, None).is_none());
    }

    #[test]
    fn fragmented_ipv4_does_not_create_transport() {
        let packet = ipv4_tcp(40, 0x2000, &[]);
        let decoded = decode_ip(&packet, None, None).unwrap();
        assert_eq!(decoded.application, "IPv4 fragment");
        assert!(decoded.transport.is_none());
    }

    #[test]
    fn udp_length_bounds_payload() {
        let packet = [0, 53, 0x13, 0x89, 0, 8, 0, 0, 1, 2, 3, 4];
        let (_, _, summary) = decode_udp(&packet).unwrap();
        assert!(summary.ends_with("0 payload bytes"));
        let malformed = [0, 53, 0x13, 0x89, 0, 16, 0, 0];
        assert!(decode_udp(&malformed).is_none());
    }

    #[test]
    fn rejects_truncated_ipv6_payload_length() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        packet.extend_from_slice(&[0; 32]);
        packet.extend_from_slice(&[0; 8]);
        assert!(decode_ip(&packet, None, None).is_none());
    }

    #[test]
    fn fragmented_ipv6_does_not_create_transport() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 8, 44, 64];
        packet.extend_from_slice(&[0; 32]);
        packet.extend_from_slice(&[6, 0, 0, 1, 0, 0, 0, 1]);
        let decoded = decode_ip(&packet, None, None).unwrap();
        assert_eq!(decoded.application, "IPv6 fragment");
        assert!(decoded.transport.is_none());
    }
}

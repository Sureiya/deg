//! Minimal pcap reader (Ethernet or raw IPv4, UDP only).
//!
//! DeG evidence is supposed to bottom out in a capture, not a spreadsheet, so
//! `rate(...)` and `sample(...)` read timestamps and payload fields directly
//! from the declared `.pcap` artifact.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub ts_us: u64,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

pub fn parse_pcap(bytes: &[u8]) -> Result<Vec<Packet>, String> {
    if bytes.len() < 24 {
        return Err("pcap is shorter than the 24-byte global header".into());
    }
    let magic = &bytes[..4];
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(format!("unknown pcap magic {magic:02x?}")),
    };
    let read_u32 = |at: usize| -> Result<u32, String> {
        let slice = bytes
            .get(at..at + 4)
            .ok_or_else(|| "truncated pcap header".to_string())?;
        let arr: [u8; 4] = slice.try_into().unwrap();
        Ok(if little {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    };
    let linktype = read_u32(20)?;
    if linktype != 1 && linktype != 101 {
        return Err(format!(
            "unsupported pcap linktype {linktype} (expected Ethernet=1 or raw IPv4=101)"
        ));
    }

    let mut packets = Vec::new();
    let mut pos = 24usize;
    while pos + 16 <= bytes.len() {
        let ts_sec = read_u32(pos)? as u64;
        let ts_frac = read_u32(pos + 4)? as u64;
        let incl_len = read_u32(pos + 8)? as usize;
        let _orig_len = read_u32(pos + 12)?;
        pos += 16;
        let data = bytes
            .get(pos..pos + incl_len)
            .ok_or_else(|| format!("truncated packet record at byte {pos}"))?;
        pos += incl_len;
        let ts_us = ts_sec * 1_000_000 + if nanos { ts_frac / 1_000 } else { ts_frac };

        let ip = if linktype == 1 {
            parse_ethernet_ipv4(data)?
        } else {
            Some(data)
        };
        let Some(ip) = ip else { continue };
        let Some(pkt) = parse_udp_ipv4(ip, ts_us) else {
            continue;
        };
        packets.push(pkt);
    }
    Ok(packets)
}

fn parse_ethernet_ipv4(data: &[u8]) -> Result<Option<&[u8]>, String> {
    if data.len() < 14 {
        return Ok(None);
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    // One or more 802.1Q tags.
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if data.len() < offset + 4 {
            return Ok(None);
        }
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }
    if ethertype != 0x0800 {
        return Ok(None);
    }
    Ok(Some(&data[offset..]))
}

fn parse_udp_ipv4(ip: &[u8], ts_us: u64) -> Option<Packet> {
    if ip.len() < 20 {
        return None;
    }
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != 17 {
        return None; // UDP
    }
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x1fff != 0 {
        return None; // non-first fragment
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let end = total_len.min(ip.len());
    if end < ihl + 8 {
        return None;
    }
    let udp = &ip[ihl..end];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let payload = udp[8..udp_len].to_vec();
    Some(Packet {
        ts_us,
        src: [ip[12], ip[13], ip[14], ip[15]],
        dst: [ip[16], ip[17], ip[18], ip[19]],
        src_port,
        dst_port,
        payload,
    })
}

pub fn span_us(packets: &[Packet]) -> u64 {
    match (packets.first(), packets.last()) {
        (Some(a), Some(b)) => b.ts_us.saturating_sub(a.ts_us),
        _ => 0,
    }
}

/// Packets whose UDP payload starts with a big-endian opcode.
pub fn filter_opcode(packets: &[Packet], opcode: u16) -> Vec<&Packet> {
    packets
        .iter()
        .filter(|p| {
            p.payload.len() >= 2 && u16::from_be_bytes([p.payload[0], p.payload[1]]) == opcode
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_capture() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());

        let payload = [0x01, 0xf4, 0xde, 0xad];
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 12]); // MACs
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut ip = Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&(ip_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.push(64);
        ip.push(17);
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&1234u16.to_be_bytes());
        ip.extend_from_slice(&27015u16.to_be_bytes());
        ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&payload);
        frame.extend_from_slice(&ip);

        out.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        out.extend_from_slice(&500_000u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
        out
    }

    #[test]
    fn parses_one_udp_packet() {
        let bytes = build_capture();
        let packets = parse_pcap(&bytes).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload, vec![0x01, 0xf4, 0xde, 0xad]);
        assert_eq!(packets[0].src_port, 1234);
        assert_eq!(packets[0].dst_port, 27015);
    }

    #[test]
    fn filters_by_opcode() {
        let packets = parse_pcap(&build_capture()).unwrap();
        assert_eq!(filter_opcode(&packets, 0x01f4).len(), 1);
        assert_eq!(filter_opcode(&packets, 0x0001).len(), 0);
    }

    #[test]
    fn rejects_short_input() {
        assert!(parse_pcap(&[1, 2, 3]).is_err());
    }
}

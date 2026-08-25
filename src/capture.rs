use serde::Serialize;

use crate::{
    decode::decode_packet,
    model::{CaptureIndex, IndexStats},
};

const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Self::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Self::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }

    fn i64(self, bytes: &[u8]) -> i64 {
        let bytes = <[u8; 8]>::try_from(bytes).expect("validated eight-byte option");
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PcapConfig {
    endian: Endian,
    fraction_to_micros: f64,
    link_type: u16,
}

#[derive(Clone, Copy, Debug)]
struct Interface {
    link_type: u16,
    snap_len: u32,
    tick_to_micros: f64,
    timestamp_offset_micros: f64,
}

#[derive(Clone, Debug, Default)]
struct PcapNgConfig {
    endian: Option<Endian>,
    interfaces: Vec<Interface>,
}

#[derive(Clone, Debug)]
enum Format {
    Unknown,
    Pcap(PcapConfig),
    PcapNg(PcapNgConfig),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParserProgress {
    pub format: String,
    pub received_bytes: u64,
    pub consumed_bytes: u64,
    pub total_bytes: u64,
    pub complete: bool,
    pub stats: IndexStats,
}

#[derive(Clone, Debug)]
pub struct CaptureParser {
    format: Format,
    buffer: Vec<u8>,
    buffer_offset: u64,
    received_bytes: u64,
    total_bytes: u64,
    complete: bool,
    index: CaptureIndex,
}

impl Default for CaptureParser {
    fn default() -> Self {
        Self {
            format: Format::Unknown,
            buffer: Vec::new(),
            buffer_offset: 0,
            received_bytes: 0,
            total_bytes: 0,
            complete: false,
            index: CaptureIndex::default(),
        }
    }
}

impl CaptureParser {
    pub fn reset(&mut self, total_bytes: u64) {
        *self = Self {
            total_bytes,
            ..Self::default()
        };
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<ParserProgress, String> {
        if self.complete {
            return Err("capture is already complete".into());
        }
        self.received_bytes = self.received_bytes.saturating_add(chunk.len() as u64);
        self.buffer.extend_from_slice(chunk);

        let consumed = match &self.format {
            Format::Unknown => self.detect_and_parse()?,
            Format::Pcap(config) => {
                parse_pcap_records(&self.buffer, self.buffer_offset, *config, &mut self.index)?
            }
            Format::PcapNg(_) => self.parse_pcapng_blocks()?,
        };
        if consumed > 0 {
            self.buffer.drain(..consumed);
            self.buffer_offset += consumed as u64;
        }
        Ok(self.progress())
    }

    pub fn finish(&mut self) -> Result<ParserProgress, String> {
        if matches!(self.format, Format::Unknown) {
            return Err("file is too short or has an unsupported capture format".into());
        }
        if !self.buffer.is_empty() {
            return Err(format!(
                "capture ended with {} bytes of an incomplete record",
                self.buffer.len()
            ));
        }
        self.complete = true;
        Ok(self.progress())
    }

    pub fn progress(&self) -> ParserProgress {
        ParserProgress {
            format: match self.format {
                Format::Unknown => "detecting",
                Format::Pcap(_) => "pcap",
                Format::PcapNg(_) => "pcapng",
            }
            .into(),
            received_bytes: self.received_bytes,
            consumed_bytes: self.buffer_offset,
            total_bytes: self.total_bytes,
            complete: self.complete,
            stats: self.index.stats(),
        }
    }

    pub fn index(&self) -> &CaptureIndex {
        &self.index
    }

    fn detect_and_parse(&mut self) -> Result<usize, String> {
        if self.buffer.len() < 4 {
            return Ok(0);
        }
        let magic = &self.buffer[..4];
        if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            self.format = Format::PcapNg(PcapNgConfig::default());
            return self.parse_pcapng_blocks();
        }
        if self.buffer.len() < 24 {
            return Ok(0);
        }
        let (endian, fraction_to_micros) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, 1.0),
            [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, 1.0),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, 0.001),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, 0.001),
            _ => return Err("unsupported file: expected PCAP or PCAPNG magic bytes".into()),
        };
        let link_type = endian.u32(&self.buffer[20..24]) as u16;
        let config = PcapConfig {
            endian,
            fraction_to_micros,
            link_type,
        };
        self.format = Format::Pcap(config);
        let records = parse_pcap_records(
            &self.buffer[24..],
            self.buffer_offset + 24,
            config,
            &mut self.index,
        )?;
        Ok(24 + records)
    }

    fn parse_pcapng_blocks(&mut self) -> Result<usize, String> {
        let Format::PcapNg(config) = &mut self.format else {
            return Ok(0);
        };
        let mut cursor = 0usize;
        while self.buffer.len().saturating_sub(cursor) >= 12 {
            let bytes = &self.buffer[cursor..];
            let is_section = bytes[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
            let endian = if is_section {
                if bytes.len() < 12 {
                    break;
                }
                match &bytes[8..12] {
                    [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                    [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                    _ => return Err("invalid PCAPNG byte-order magic".into()),
                }
            } else if let Some(endian) = config.endian {
                endian
            } else {
                return Err("PCAPNG data appeared before a section header".into());
            };
            let block_type = endian.u32(&bytes[0..4]);
            let block_len = endian.u32(&bytes[4..8]) as usize;
            if !(12..=MAX_BLOCK_SIZE).contains(&block_len) || !block_len.is_multiple_of(4) {
                return Err(format!("invalid PCAPNG block length: {block_len}"));
            }
            if is_section && block_len < 28 {
                return Err("PCAPNG section header is shorter than 28 bytes".into());
            }
            if bytes.len() < block_len {
                break;
            }
            if endian.u32(&bytes[block_len - 4..block_len]) as usize != block_len {
                return Err("PCAPNG block length trailer does not match".into());
            }

            match block_type {
                0x0a0d0d0a => {
                    config.endian = Some(endian);
                    config.interfaces.clear();
                }
                1 => parse_interface_block(&bytes[..block_len], endian, config)?,
                6 => parse_enhanced_packet(
                    &bytes[..block_len],
                    endian,
                    config,
                    self.buffer_offset + cursor as u64,
                    &mut self.index,
                )?,
                3 => parse_simple_packet(
                    &bytes[..block_len],
                    endian,
                    config,
                    self.buffer_offset + cursor as u64,
                    &mut self.index,
                )?,
                _ => {}
            }
            cursor += block_len;
        }
        Ok(cursor)
    }
}

fn parse_pcap_records(
    buffer: &[u8],
    buffer_offset: u64,
    config: PcapConfig,
    index: &mut CaptureIndex,
) -> Result<usize, String> {
    let mut cursor = 0usize;
    while buffer.len().saturating_sub(cursor) >= 16 {
        let header = &buffer[cursor..cursor + 16];
        let seconds = config.endian.u32(&header[0..4]) as f64;
        let fraction = config.endian.u32(&header[4..8]) as f64;
        let captured_len = config.endian.u32(&header[8..12]);
        let wire_len = config.endian.u32(&header[12..16]);
        if captured_len as usize > MAX_BLOCK_SIZE {
            return Err(format!("PCAP packet is too large: {captured_len} bytes"));
        }
        let record_len = 16 + captured_len as usize;
        if buffer.len().saturating_sub(cursor) < record_len {
            break;
        }
        let packet_offset = buffer_offset + cursor as u64 + 16;
        let packet = &buffer[cursor + 16..cursor + record_len];
        index.add_packet(
            seconds * 1_000_000.0 + fraction * config.fraction_to_micros,
            packet_offset,
            captured_len,
            wire_len,
            decode_packet(config.link_type, packet),
        );
        cursor += record_len;
    }
    Ok(cursor)
}

fn parse_interface_block(
    block: &[u8],
    endian: Endian,
    config: &mut PcapNgConfig,
) -> Result<(), String> {
    if block.len() < 20 {
        return Err("truncated PCAPNG interface block".into());
    }
    let link_type = endian.u16(&block[8..10]);
    let snap_len = endian.u32(&block[12..16]);
    let mut tick_to_micros = 1.0;
    let mut timestamp_offset_micros = 0.0;
    let mut cursor = 16usize;
    let options_end = block.len() - 4;
    while cursor + 4 <= options_end {
        let code = endian.u16(&block[cursor..cursor + 2]);
        let length = endian.u16(&block[cursor + 2..cursor + 4]) as usize;
        cursor += 4;
        if code == 0 {
            break;
        }
        if cursor + length > options_end {
            return Err("truncated PCAPNG interface option".into());
        }
        if code == 9 && length >= 1 {
            let resolution = block[cursor];
            tick_to_micros = if resolution & 0x80 == 0 {
                1_000_000.0 / 10f64.powi(resolution as i32)
            } else {
                1_000_000.0 / 2f64.powi((resolution & 0x7f) as i32)
            };
        } else if code == 14 && length == 8 {
            timestamp_offset_micros = endian.i64(&block[cursor..cursor + 8]) as f64 * 1_000_000.0;
        }
        cursor += (length + 3) & !3;
    }
    config.interfaces.push(Interface {
        link_type,
        snap_len,
        tick_to_micros,
        timestamp_offset_micros,
    });
    Ok(())
}

fn parse_enhanced_packet(
    block: &[u8],
    endian: Endian,
    config: &PcapNgConfig,
    block_offset: u64,
    index: &mut CaptureIndex,
) -> Result<(), String> {
    if block.len() < 32 {
        return Err("truncated PCAPNG enhanced packet block".into());
    }
    let interface_id = endian.u32(&block[8..12]) as usize;
    let interface = config
        .interfaces
        .get(interface_id)
        .ok_or_else(|| format!("PCAPNG packet references missing interface {interface_id}"))?;
    let timestamp = ((endian.u32(&block[12..16]) as u64) << 32) | endian.u32(&block[16..20]) as u64;
    let captured_len = endian.u32(&block[20..24]);
    let wire_len = endian.u32(&block[24..28]);
    if captured_len as usize > MAX_BLOCK_SIZE || 28 + captured_len as usize > block.len() - 4 {
        return Err("invalid PCAPNG captured packet length".into());
    }
    let packet = &block[28..28 + captured_len as usize];
    index.add_packet(
        timestamp as f64 * interface.tick_to_micros + interface.timestamp_offset_micros,
        block_offset + 28,
        captured_len,
        wire_len,
        decode_packet(interface.link_type, packet),
    );
    Ok(())
}

fn parse_simple_packet(
    block: &[u8],
    endian: Endian,
    config: &PcapNgConfig,
    block_offset: u64,
    index: &mut CaptureIndex,
) -> Result<(), String> {
    let interface = config
        .interfaces
        .first()
        .ok_or_else(|| "PCAPNG simple packet has no interface".to_owned())?;
    if block.len() < 16 {
        return Err("truncated PCAPNG simple packet block".into());
    }
    let wire_len = endian.u32(&block[8..12]);
    let padded_data_len = block.len() - 16;
    let snap_len = if interface.snap_len == 0 {
        padded_data_len
    } else {
        interface.snap_len as usize
    };
    let captured_len = padded_data_len.min(wire_len as usize).min(snap_len) as u32;
    let packet = &block[12..12 + captured_len as usize];
    index.add_packet(
        f64::NAN,
        block_offset + 12,
        captured_len,
        wire_len,
        decode_packet(interface.link_type, packet),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4_tcp() -> Vec<u8> {
        let mut packet = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 58, 0, 0, 0, 0, 64, 6, 0,
            0, 10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02,
            0xff, 0xff, 0, 0, 0, 0,
        ];
        packet.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        packet
    }

    #[test]
    fn parses_pcap_across_chunk_boundaries() {
        let packet = ethernet_ipv4_tcp();
        let mut capture = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        capture.extend_from_slice(&1u32.to_le_bytes());
        capture.extend_from_slice(&500u32.to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&packet);

        let mut parser = CaptureParser::default();
        parser.reset(capture.len() as u64);
        for chunk in capture.chunks(7) {
            parser.push(chunk).unwrap();
        }
        let progress = parser.finish().unwrap();
        assert_eq!(progress.stats.packets, 1);
        assert_eq!(progress.stats.flows, 1);
        assert_eq!(progress.stats.entities, 2);
        let row = &parser.index().rows(0, 1)[0];
        assert_eq!(row.protocol, "HTTP/1");
        assert_eq!(row.source, "10.0.0.1");
        assert!(parser.index().flow(row.flow_id.unwrap()).is_some());
    }

    #[test]
    fn parses_pcapng_interface_timestamp_resolution() {
        let packet = ethernet_ipv4_tcp();
        let mut capture = Vec::new();
        append_pcapng_block(
            &mut capture,
            0x0a0d0d0a,
            &[
                0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        );
        append_pcapng_block(
            &mut capture,
            1,
            &[
                1, 0, 0, 0, 0xff, 0xff, 0, 0, // Ethernet + snap length
                9, 0, 1, 0, 9, 0, 0, 0, // if_tsresol = 10^-9
                14, 0, 8, 0, 2, 0, 0, 0, 0, 0, 0, 0, // if_tsoffset = 2 seconds
                0, 0, 0, 0, // end of options
            ],
        );
        let mut enhanced = Vec::new();
        enhanced.extend_from_slice(&0u32.to_le_bytes());
        enhanced.extend_from_slice(&0u32.to_le_bytes());
        enhanced.extend_from_slice(&1000u32.to_le_bytes());
        enhanced.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        enhanced.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        enhanced.extend_from_slice(&packet);
        while enhanced.len() % 4 != 0 {
            enhanced.push(0);
        }
        append_pcapng_block(&mut capture, 6, &enhanced);

        let mut parser = CaptureParser::default();
        parser.reset(capture.len() as u64);
        for chunk in capture.chunks(11) {
            parser.push(chunk).unwrap();
        }
        let progress = parser.finish().unwrap();
        assert_eq!(progress.format, "pcapng");
        assert_eq!(progress.stats.packets, 1);
        assert_eq!(parser.index().rows(0, 1)[0].timestamp_micros, 2_000_001.0);
    }

    #[test]
    fn rejects_short_pcapng_section_header() {
        let mut capture = Vec::new();
        append_pcapng_block(&mut capture, 0x0a0d0d0a, &[0x4d, 0x3c, 0x2b, 0x1a]);
        let mut parser = CaptureParser::default();
        parser.reset(capture.len() as u64);
        assert!(parser.push(&capture).is_err());
    }

    fn append_pcapng_block(capture: &mut Vec<u8>, block_type: u32, body: &[u8]) {
        let length = (12 + body.len()) as u32;
        capture.extend_from_slice(&block_type.to_le_bytes());
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(body);
        capture.extend_from_slice(&length.to_le_bytes());
    }
}

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use crate::decode::{DecodedPacket, Transport};

pub type PacketId = u64;
pub type FlowId = u64;
pub type EntityId = u64;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketRow {
    pub id: PacketId,
    pub file_offset: u64,
    pub timestamp_micros: f64,
    pub captured_len: u32,
    pub wire_len: u32,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub summary: String,
    pub flow_id: Option<FlowId>,
    pub source_entity: Option<EntityId>,
    pub destination_entity: Option<EntityId>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowView {
    pub id: FlowId,
    pub transport: String,
    pub application: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub started_micros: f64,
    pub ended_micros: f64,
    pub packet_count: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
}

#[derive(Clone, Debug)]
struct Flow {
    id: FlowId,
    transport: Transport,
    application: String,
    endpoint_a: String,
    endpoint_b: String,
    started_micros: f64,
    ended_micros: f64,
    bytes_a_to_b: u64,
    bytes_b_to_a: u64,
    packet_ids: Vec<PacketId>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    transport: Transport,
    endpoint_a: String,
    endpoint_b: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitySummary {
    pub id: EntityId,
    pub label: String,
    pub addresses: Vec<String>,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub flow_count: u64,
}

#[derive(Clone, Debug, Default)]
struct Entity {
    addresses: BTreeSet<String>,
    packets_in: u64,
    packets_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    flow_ids: BTreeSet<FlowId>,
}

#[derive(Clone, Debug, Default)]
struct EntityStore {
    entities: Vec<Entity>,
    parent: Vec<usize>,
    address_to_entity: HashMap<String, usize>,
    active_entity_count: usize,
}

impl EntityStore {
    fn root(&self, mut id: usize) -> usize {
        while self.parent.get(id).copied().unwrap_or(id) != id {
            id = self.parent[id];
        }
        id
    }

    fn entity_for(&mut self, address: &str) -> usize {
        if let Some(&id) = self.address_to_entity.get(address) {
            return self.root(id);
        }
        let id = self.entities.len();
        let mut entity = Entity::default();
        entity.addresses.insert(address.to_owned());
        self.entities.push(entity);
        self.parent.push(id);
        self.address_to_entity.insert(address.to_owned(), id);
        self.active_entity_count += 1;
        id
    }

    fn associate(&mut self, addresses: &[String]) -> Option<usize> {
        let mut ids = addresses
            .iter()
            .filter(|address| !address.is_empty())
            .map(|address| self.entity_for(address))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        let root = *ids.first()?;
        for other in ids.into_iter().skip(1) {
            self.merge(root, other);
        }
        for address in addresses {
            if !address.is_empty() {
                self.address_to_entity.insert(address.clone(), root);
                self.entities[root].addresses.insert(address.clone());
            }
        }
        Some(root)
    }

    fn merge(&mut self, left: usize, right: usize) {
        let left = self.root(left);
        let right = self.root(right);
        if left == right {
            return;
        }
        let (keep, remove) = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        self.parent[remove] = keep;
        self.active_entity_count -= 1;
        let removed = std::mem::take(&mut self.entities[remove]);
        for address in removed.addresses {
            self.address_to_entity.insert(address.clone(), keep);
            self.entities[keep].addresses.insert(address);
        }
        self.entities[keep].packets_in += removed.packets_in;
        self.entities[keep].packets_out += removed.packets_out;
        self.entities[keep].bytes_in += removed.bytes_in;
        self.entities[keep].bytes_out += removed.bytes_out;
        self.entities[keep].flow_ids.extend(removed.flow_ids);
    }

    fn record_packet(
        &mut self,
        source: Option<usize>,
        destination: Option<usize>,
        bytes: u64,
        flow_id: Option<FlowId>,
    ) {
        if let Some(source) = source.map(|id| self.root(id)) {
            let entity = &mut self.entities[source];
            entity.packets_out += 1;
            entity.bytes_out += bytes;
            if let Some(flow_id) = flow_id {
                entity.flow_ids.insert(flow_id);
            }
        }
        if let Some(destination) = destination.map(|id| self.root(id)) {
            let entity = &mut self.entities[destination];
            entity.packets_in += 1;
            entity.bytes_in += bytes;
            if let Some(flow_id) = flow_id {
                entity.flow_ids.insert(flow_id);
            }
        }
    }

    fn summary(&self, id: usize) -> Option<EntitySummary> {
        let root = self.root(id);
        let entity = self.entities.get(root)?;
        if entity.addresses.is_empty() {
            return None;
        }
        let addresses = entity.addresses.iter().cloned().collect::<Vec<_>>();
        let label = addresses
            .iter()
            .find(|address| {
                address.contains('.') || address.contains(':') && !address.contains('-')
            })
            .cloned()
            .unwrap_or_else(|| addresses[0].clone());
        Some(EntitySummary {
            id: root as EntityId,
            label,
            addresses,
            packets_in: entity.packets_in,
            packets_out: entity.packets_out,
            bytes_in: entity.bytes_in,
            bytes_out: entity.bytes_out,
            flow_count: entity.flow_ids.len() as u64,
        })
    }

    fn count(&self) -> usize {
        self.active_entity_count
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexStats {
    pub packets: u64,
    pub flows: u64,
    pub entities: u64,
    pub captured_bytes: u64,
    pub malformed_packets: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CaptureIndex {
    rows: Vec<PacketRow>,
    flows: Vec<Flow>,
    flow_lookup: HashMap<FlowKey, FlowId>,
    entities: EntityStore,
    stats: IndexStats,
}

impl CaptureIndex {
    pub fn add_packet(
        &mut self,
        timestamp_micros: f64,
        file_offset: u64,
        captured_len: u32,
        wire_len: u32,
        decoded: Option<DecodedPacket>,
    ) {
        let packet_id = self.rows.len() as PacketId;
        self.stats.packets += 1;
        self.stats.captured_bytes += captured_len as u64;

        let Some(decoded) = decoded else {
            self.stats.malformed_packets += 1;
            self.rows.push(PacketRow {
                id: packet_id,
                file_offset,
                timestamp_micros,
                captured_len,
                wire_len,
                protocol: "Unknown".into(),
                source: "—".into(),
                destination: "—".into(),
                summary: "Unsupported or truncated packet".into(),
                flow_id: None,
                source_entity: None,
                destination_entity: None,
            });
            return;
        };

        for association in &decoded.address_associations {
            self.entities.associate(association);
        }
        let source_entity = decoded
            .source_addresses
            .first()
            .map(|address| self.entities.entity_for(address));
        let destination_entity = decoded
            .destination_addresses
            .first()
            .map(|address| self.entities.entity_for(address));

        let flow_id = decoded.transport.as_ref().map(|transport| {
            let source_endpoint = format!("{}:{}", decoded.source, transport.source_port);
            let destination_endpoint =
                format!("{}:{}", decoded.destination, transport.destination_port);
            let (endpoint_a, endpoint_b, a_to_b) = if source_endpoint <= destination_endpoint {
                (source_endpoint, destination_endpoint, true)
            } else {
                (destination_endpoint, source_endpoint, false)
            };
            let key = FlowKey {
                transport: transport.kind,
                endpoint_a: endpoint_a.clone(),
                endpoint_b: endpoint_b.clone(),
            };
            let id = if let Some(id) = self.flow_lookup.get(&key).copied() {
                id
            } else {
                let id = self.flows.len() as FlowId;
                self.flow_lookup.insert(key, id);
                self.flows.push(Flow {
                    id,
                    transport: transport.kind,
                    application: decoded.application.clone(),
                    endpoint_a,
                    endpoint_b,
                    started_micros: timestamp_micros,
                    ended_micros: timestamp_micros,
                    bytes_a_to_b: 0,
                    bytes_b_to_a: 0,
                    packet_ids: Vec::new(),
                });
                id
            };
            let flow = &mut self.flows[id as usize];
            if timestamp_micros.is_finite() {
                if !flow.started_micros.is_finite() || timestamp_micros < flow.started_micros {
                    flow.started_micros = timestamp_micros;
                }
                if !flow.ended_micros.is_finite() || timestamp_micros > flow.ended_micros {
                    flow.ended_micros = timestamp_micros;
                }
            }
            if flow.application == flow.transport.label() && decoded.application != flow.application
            {
                flow.application = decoded.application.clone();
            }
            if a_to_b {
                flow.bytes_a_to_b += wire_len as u64;
            } else {
                flow.bytes_b_to_a += wire_len as u64;
            }
            flow.packet_ids.push(packet_id);
            id
        });

        self.entities
            .record_packet(source_entity, destination_entity, wire_len as u64, flow_id);
        self.stats.flows = self.flows.len() as u64;
        self.stats.entities = self.entities.count() as u64;

        self.rows.push(PacketRow {
            id: packet_id,
            file_offset,
            timestamp_micros,
            captured_len,
            wire_len,
            protocol: decoded.application,
            source: decoded.source,
            destination: decoded.destination,
            summary: decoded.summary,
            flow_id,
            source_entity: source_entity.map(|id| self.entities.root(id) as EntityId),
            destination_entity: destination_entity.map(|id| self.entities.root(id) as EntityId),
        });
    }

    pub fn stats(&self) -> IndexStats {
        let mut stats = self.stats.clone();
        stats.entities = self.entities.count() as u64;
        stats
    }

    pub fn rows(&self, start: usize, count: usize) -> Vec<PacketRow> {
        self.rows
            .iter()
            .skip(start)
            .take(count.min(2_000))
            .cloned()
            .map(|mut row| {
                row.source_entity = row
                    .source_entity
                    .map(|id| self.entities.root(id as usize) as EntityId);
                row.destination_entity = row
                    .destination_entity
                    .map(|id| self.entities.root(id as usize) as EntityId);
                row
            })
            .collect()
    }

    pub fn flow(&self, id: FlowId) -> Option<FlowView> {
        let flow = self.flows.get(id as usize)?;
        Some(FlowView {
            id: flow.id,
            transport: flow.transport.label().to_owned(),
            application: flow.application.clone(),
            endpoint_a: flow.endpoint_a.clone(),
            endpoint_b: flow.endpoint_b.clone(),
            started_micros: flow.started_micros,
            ended_micros: flow.ended_micros,
            packet_count: flow.packet_ids.len() as u64,
            bytes_a_to_b: flow.bytes_a_to_b,
            bytes_b_to_a: flow.bytes_b_to_a,
        })
    }

    pub fn flow_rows(&self, id: FlowId, start: usize, count: usize) -> Vec<PacketRow> {
        let Some(flow) = self.flows.get(id as usize) else {
            return Vec::new();
        };
        flow.packet_ids
            .iter()
            .skip(start)
            .take(count.min(2_000))
            .filter_map(|packet_id| self.rows.get(*packet_id as usize))
            .cloned()
            .map(|mut row| {
                row.source_entity = row
                    .source_entity
                    .map(|entity_id| self.entities.root(entity_id as usize) as EntityId);
                row.destination_entity = row
                    .destination_entity
                    .map(|entity_id| self.entities.root(entity_id as usize) as EntityId);
                row
            })
            .collect()
    }

    pub fn entity(&self, id: EntityId) -> Option<EntitySummary> {
        self.entities.summary(id as usize)
    }

    pub fn entity_flows(&self, id: EntityId, start: usize, count: usize) -> Vec<FlowView> {
        let root = self.entities.root(id as usize);
        let Some(entity) = self.entities.entities.get(root) else {
            return Vec::new();
        };
        entity
            .flow_ids
            .iter()
            .skip(start)
            .take(count.min(500))
            .filter_map(|flow_id| self.flow(*flow_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_entity_count_tracks_merges() {
        let mut entities = EntityStore::default();
        let first = entities.entity_for("10.0.0.1");
        let second = entities.entity_for("00-01-02-03-04-05");
        assert_eq!(entities.count(), 2);

        entities.associate(&["10.0.0.1".into(), "00-01-02-03-04-05".into()]);
        assert_eq!(entities.count(), 1);
        assert_eq!(entities.root(first), entities.root(second));

        entities.associate(&["10.0.0.1".into(), "00-01-02-03-04-05".into()]);
        assert_eq!(entities.count(), 1);
    }

    #[test]
    fn flow_timestamps_ignore_nan_and_track_out_of_order_bounds() {
        use crate::decode::TransportInfo;

        let packet = || DecodedPacket {
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            source_addresses: vec!["10.0.0.1".into()],
            destination_addresses: vec!["10.0.0.2".into()],
            address_associations: Vec::new(),
            transport: Some(TransportInfo {
                kind: Transport::Tcp,
                source_port: 1234,
                destination_port: 80,
            }),
            application: "HTTP/1".into(),
            summary: "test".into(),
        };
        let mut index = CaptureIndex::default();
        index.add_packet(f64::NAN, 0, 40, 40, Some(packet()));
        index.add_packet(20.0, 40, 40, 40, Some(packet()));
        index.add_packet(10.0, 80, 40, 40, Some(packet()));
        let flow = index.flow(0).unwrap();
        assert_eq!(flow.started_micros, 10.0);
        assert_eq!(flow.ended_micros, 20.0);
    }
}

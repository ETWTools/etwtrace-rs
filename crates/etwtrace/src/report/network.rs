//! TCP/IP and UDP (-tcpip or -udp; the kernel logs both) and DNS client queries (-dns).

use std::collections::VecDeque;

use super::Shared;
use super::common::{Operations, Out, ProcessTally, StackKind, Tally, dotnet_cmp, outln};
use super::event::{Event, Kind, Tcp, Udp};
use super::payload::Payload;
use crate::hash::FxMap;
use crate::text::{self, pad_left, pad_right};

/// Bytes sent and received by process and by remote endpoint, and TCP connection events and UDP failures.  TCP events
/// give the remote endpoint as the destination for sends and receives alike, but UDP events follow the packet: a
/// receive's remote endpoint is its source.
#[derive(Default)]
pub struct NetworkSummary {
    tcp: Traffic,
    udp: Traffic,
}

impl NetworkSummary {
    pub fn on_event(&mut self, event: &Event<'_>) {
        let p = event.payload;
        let pid = event.process_id;
        let v = event.version;
        match event.kind {
            Kind::Tcp(Tcp::Send) => self.tcp.add(pid, Endpoint::v4(&p, 8, 16), p.i32(4), true),
            Kind::Tcp(Tcp::SendV6) => self.tcp.add(pid, Endpoint::v6(&p, 8, 40), p.i32(4), true),
            Kind::Tcp(Tcp::Recv) => {
                let (size, address, port) = if v >= 1 { (4, 8, 16) } else { (12, 0, 8) };
                self.tcp.add(pid, Endpoint::v4(&p, address, port), p.i32(size), false);
            }
            Kind::Tcp(Tcp::RecvV6) => self.tcp.add(pid, Endpoint::v6(&p, 8, 40), p.i32(4), false),
            Kind::Tcp(Tcp::Connect | Tcp::ConnectV6) => self.tcp.event(CONNECT),
            Kind::Tcp(Tcp::Accept | Tcp::AcceptV6) => self.tcp.event(ACCEPT),
            Kind::Tcp(Tcp::Disconnect | Tcp::DisconnectV6) => self.tcp.event(DISCONNECT),
            Kind::Tcp(Tcp::Retransmit | Tcp::RetransmitV6) => self.tcp.event(RETRANSMIT),
            Kind::Tcp(Tcp::Fail) => self.tcp.event(FAILURE),
            Kind::Udp(Udp::Send) => {
                let (size, address, port) = if v >= 1 { (p.i32(4), 8, 16) } else { (i32::from(p.i16(p.host(10, 1))), p.host(12, 1), p.host(16, 1)) };
                self.udp.add(pid, Endpoint::v4(&p, address, port), size, true);
            }
            Kind::Udp(Udp::Recv) => {
                let (size, address, port) = if v >= 1 { (p.i32(4), 12, 18) } else { (i32::from(p.i16(p.host(10, 1))), p.host(4, 1), p.host(8, 1)) };
                self.udp.add(pid, Endpoint::v4(&p, address, port), size, false);
            }
            Kind::Udp(Udp::SendV6) => self.udp.add(pid, Endpoint::v6(&p, 8, 40), p.i32(4), true),
            Kind::Udp(Udp::RecvV6) => self.udp.add(pid, Endpoint::v6(&p, 24, 42), p.i32(4), false),
            Kind::Udp(Udp::Fail) => self.udp.event(FAILURE),
            _ => {}
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        self.tcp.print("TCP/IP", shared, out);
        self.udp.print("UDP", shared, out);
    }
}

const CONNECT: usize = 0;
const ACCEPT: usize = 1;
const DISCONNECT: usize = 2;
const RETRANSMIT: usize = 3;
const FAILURE: usize = 4;
const EVENT_NAMES: [&str; 5] = ["connect", "accept", "disconnect", "retransmit", "failure"];

/// A remote endpoint: the address bytes in network order (IPv4 in the first four) and the port.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Endpoint {
    v6: bool,
    address: [u8; 16],
    port: u16,
}

impl Endpoint {
    fn v4(p: &Payload<'_>, address: usize, port: usize) -> Self {
        let [a, b, c, d] = p.array::<4>(address);
        let address = [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Self {
            v6: false,
            address,
            port: u16::from_be_bytes(p.array(port)),
        }
    }

    fn v6(p: &Payload<'_>, address: usize, port: usize) -> Self {
        Self {
            v6: true,
            address: p.array(address),
            port: u16::from_be_bytes(p.array(port)),
        }
    }

    fn label(&self) -> String {
        if self.v6 {
            format!("[{}]:{}", text::ipv6(self.address), self.port)
        } else {
            let [a, b, c, d, ..] = self.address;
            format!("{}:{}", text::ipv4([a, b, c, d]), self.port)
        }
    }
}

/// The sends and receives of one protocol.
#[derive(Default)]
struct Traffic {
    sent: Operations,
    received: Operations,
    by_process: ProcessTally,
    by_endpoint: FxMap<Endpoint, i64>,
    events: [i64; 5],
}

impl Traffic {
    fn add(&mut self, process_id: i32, endpoint: Endpoint, size: i32, is_send: bool) {
        let size = i64::from(size);
        if is_send { &mut self.sent } else { &mut self.received }.add(size, 0.0);
        self.by_process.add(process_id, -1, size);
        let bytes = self.by_endpoint.entry(endpoint).or_insert(0);
        *bytes = bytes.wrapping_add(size);
    }

    fn event(&mut self, index: usize) {
        if let Some(count) = self.events.get_mut(index) {
            *count = count.wrapping_add(1);
        }
    }

    fn print(&self, protocol: &str, shared: &Shared, out: &mut Out) {
        let mut events = Tally::new();
        for (name, &count) in EVENT_NAMES.iter().zip(&self.events) {
            if count > 0 {
                events.add(name, count);
            }
        }

        let transfers = self.sent.count.wrapping_add(self.received.count);
        if transfers.wrapping_add(events.total()) == 0 {
            return;
        }

        outln!(out);
        let events_text = if events.total() > 0 { format!("; {}", events.describe(8)) } else { String::new() };
        outln!(
            out,
            "{protocol}: sent {} in {} sends, received {} in {} receives{events_text}",
            text::bytes(self.sent.bytes),
            text::count(self.sent.count),
            text::bytes(self.received.bytes),
            text::count(self.received.count)
        );
        if transfers > 0 {
            self.by_process.by_process(&shared.processes).print(out, "sent+recv", "process", text::bytes, 8);
            let mut by_endpoint = Tally::new();
            for (endpoint, &bytes) in &self.by_endpoint {
                by_endpoint.add(&endpoint.label(), bytes);
            }

            by_endpoint.print(out, "sent+recv", "remote endpoint", text::bytes, 8);
        }
    }
}

/// DNS client queries, from Microsoft-Windows-DNS-Client's "query called" (3006) and "query completed" (3008) events,
/// which the querying process logs.  A completion is matched to the oldest pending call with the same process, name
/// and type.  Both events start QueryName (a string), QueryType (UInt32) and QueryOptions (UInt64); 3008 then has
/// QueryStatus (UInt32).
#[derive(Default)]
pub struct DnsSummary {
    events: i64,
    pending: FxMap<(i32, String, i64), VecDeque<f64>>,
    queries: Vec<DnsQuery>,
}

struct DnsQuery {
    name: String,
    query_type: i64,
    status: i64,
    msec: f64,
    process_id: i32,
}

const QUERY_CALLED: u16 = 3006;
const QUERY_COMPLETED: u16 = 3008;

impl DnsSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        if event.kind != Kind::Dns {
            return;
        }

        self.events = self.events.wrapping_add(1);
        shared.stacks.count(StackKind::Dns, event.has_attached_stack());
        let id = event.record.id();
        if id != QUERY_CALLED && id != QUERY_COMPLETED {
            return;
        }

        let p = event.payload;
        let name = p.utf16(0);
        let after_name = p.skip_utf16(0);
        let query_type = i64::from(p.u32(after_name));
        let time = shared.relative_msec(event);
        let starts = self.pending.entry((event.process_id, name.clone(), query_type)).or_default();
        if id == QUERY_CALLED {
            starts.push_back(time);
            return;
        }

        let msec = starts.pop_front().map_or(f64::NAN, |start| time - start);
        let status = i64::from(p.u32(after_name.saturating_add(12)));
        self.queries.push(DnsQuery {
            name,
            query_type,
            status,
            msec,
            process_id: event.process_id,
        });
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.events == 0 {
            return;
        }

        let failed = self.queries.iter().filter(|query| query.status != 0).count();
        let mut processes: Vec<i32> = self.queries.iter().map(|query| query.process_id).collect();
        processes.sort_unstable();
        processes.dedup();
        outln!(out);
        outln!(
            out,
            "DNS: {} DNS client events; {} queries completed in {} processes, {failed} with an error status; slowest:",
            text::count(self.events),
            self.queries.len(),
            processes.len()
        );
        outln!(out, "  {}  {} {} {} process", pad_left("ms", 9), pad_right("status", 10), pad_right("type", 6), pad_right("name", 40));
        let mut slowest: Vec<&DnsQuery> = self.queries.iter().collect();
        slowest.sort_by(|a, b| dotnet_cmp(b.msec, a.msec));
        for query in slowest.into_iter().take(10) {
            let ms = if query.msec.is_nan() { "?".to_owned() } else { text::fixed(query.msec, 1) };
            outln!(
                out,
                "  {}  {} {} {} {}",
                pad_left(&ms, 9),
                pad_right(&status_name(query.status), 10),
                pad_right(&type_name(query.query_type), 6),
                pad_right(&query.name, 40),
                shared.processes.label(query.process_id)
            );
        }
    }
}

fn type_name(query_type: i64) -> String {
    match query_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        _ => return query_type.to_string(),
    }
    .to_owned()
}

fn status_name(status: i64) -> String {
    match status {
        0 => "ok",
        1460 => "timeout",
        9003 => "NXDOMAIN",
        9501 => "no records",
        11001 => "not found",
        _ => return status.to_string(),
    }
    .to_owned()
}

/* 
    NetCrawler – Multi-vendor / dual-stack topology crawler (2026-02-06)    
    Copyright (C) 2025-2026 Francis Booth

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/

use anyhow::{Context, Result};
use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use dashmap::{DashMap, DashSet};
use once_cell::sync::{Lazy, OnceCell};
use petgraph::{
    graph::{Graph, NodeIndex},
    Undirected,
};
use regex::Regex;
use ssh2::{Channel, ErrorCode, Session};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::sleep,
    time::{Duration, Instant},
};
use threadpool::ThreadPool;

/* ───── type aliases ───── */
type UGraph  = Graph<String, u8, Undirected>;
type HostMap = DashMap<String, String>; // hostname → canonical IP

/* ───── vendor selection ───── */
#[derive(Clone, Copy, PartialEq, Eq)]
enum Vendor {
    Cisco,
    Extreme,
    Dell,
    Auto, // default: try Cisco first, then LLDP
}

/* ───── address family ───── */
#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily { V4, V6 }

// Support V4 and V6 IP addresses

fn family_of(ip: &str) -> IpFamily {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => IpFamily::V4,
        Ok(IpAddr::V6(_)) => IpFamily::V6,
        _                 => IpFamily::V4,
    }
}

/* ───── run-time options ───── */
#[derive(Clone, Copy)]
struct Opts {
    site_check: bool,
    vendor:     Vendor,
    fam:        IpFamily,
}

/* ───── constants ───── */
const SSH_PORT: u16        = 22;
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const SSH_TIMEOUT_MS: u32   = 10_000;
const READ_LIMIT: Duration  = Duration::from_secs(10);
const WORKER_POLL: Duration = Duration::from_millis(200);

/* ───── global site prefix ───── */
static SITE_PREFIX: OnceCell<String> = OnceCell::new();

/* ───── sets for de-duplication ───── */
static VISITED: Lazy<DashSet<String>> = Lazy::new(|| DashSet::new());

/* ───── regexes (unchanged) ───── */
static IP_V4_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b").unwrap());
static IP_V6_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\b").unwrap());

static HOST_VER:    Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^ *([A-Za-z0-9._-]+) +uptime is").unwrap());
static HOST_RUN:    Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^hostname +(.*?)\r?$").unwrap());
static HOST_SHHOST: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^Hostname: +(.*?)\r?$").unwrap());
static HOST_SYSNAME:Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^ *SysName:\s*(\S+)").unwrap());

static CDP_ID:        Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*Device ID:\s*([A-Za-z0-9._-]+)").unwrap());
static LLDP_SYSNAME:  Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*(?:Sys|System)\s*Name(?:\s+TLV)?\s*:\s*([\w.-]+)").unwrap());
//static LLDP_MGMT:     Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*Management\s+Address\s*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})").unwrap());

/* ───── helpers ───── */
fn site_of(host: &str) -> &str { host.split('-').next().unwrap_or(host) }

fn extract_ips(txt: &str, fam: IpFamily) -> Vec<String> {
    let result = match fam { IpFamily::V4 => &IP_V4_RE, IpFamily::V6 => &IP_V6_RE };
    result.captures_iter(txt)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn canon_addr(raw: &str) -> String {
    IpAddr::from_str(raw).map(|a| a.to_string()).unwrap_or_else(|_| raw.to_string())
}

fn canon(ip: &str, aliases: &DashMap<String, String>) -> String {
    aliases.get(&canon_addr(ip)).map(|v| v.value().clone()).unwrap_or_else(|| canon_addr(ip))
}

fn is_ios(s: &str) -> bool { s.to_ascii_lowercase().contains("cisco ios") }

fn connect_ssh(ip: &str) -> Result<TcpStream> {
    let addr = if ip.contains(':') { format!("[{ip}]:{SSH_PORT}") }
               else                { format!("{ip}:{SSH_PORT}") };
    let sa: SocketAddr = addr.to_socket_addrs()?.next().context("resolve")?;
    TcpStream::connect_timeout(&sa, TCP_TIMEOUT)
        .with_context(|| format!("TCP connect to {ip}"))
}

/* ───── neighbor parsing ───── */
fn neighbours(txt: &str, fam: IpFamily) -> Vec<(String, String)> {
    let ip_result = match fam { IpFamily::V4 => &IP_V4_RE, IpFamily::V6 => &IP_V6_RE };
    let mut result      = Vec::new();
    let mut cur_host = String::new();

    for l in txt.lines() {
        if let Some(c) = CDP_ID.captures(l) {
            cur_host = c[1].trim().to_string();
            continue;
        }
        if let Some(c) = LLDP_SYSNAME.captures(l) {
            cur_host = c[1].trim().to_string();
            continue;
        }

        if let Some(pos) = l.to_ascii_lowercase().find("management address") {
            if !cur_host.is_empty() {
                if let Some(c) = ip_result.captures(&l[pos..]) {
                    result.push((c[1].to_string(), cur_host.clone()));
                }
            }
            continue;
        }

        if !cur_host.is_empty() {
            if let Some(c) = ip_result.captures(l) {
                result.push((c[1].to_string(), cur_host.clone()));
            }
        }
    }

    result.into_iter().filter(|(ip, _)| family_of(ip) == fam).collect()
}

// Terrible attempt at trying to build the topology graph with lower number IP switches
// going "left" and higher number IP switches going to the "right". 
// It doesn't work but I keep the code around because otherwise the graph doesn't generate correctly.
fn ip_score(ip: &str) -> Option<u32> {
    let mut o = ip.split('.').flat_map(|p| p.parse::<u8>());
    Some(((o.next()? as u32) << 24)
        | ((o.next()? as u32) << 16)
        | ((o.next()? as u32) <<  8)
        |  (o.next()? as u32))
}

/* ───── SSH helpers ───── */
fn read_all(mut ch: Channel) -> Result<String> {
    let mut out = String::new();
    let mut buf = [0u8; 8192];
    let deadline = Instant::now() + READ_LIMIT;

    loop {
        match ch.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(e) => {
                if let Some(se) = e.get_ref().and_then(|x| x.downcast_ref::<ssh2::Error>()) {
                    match se.code() {
                        ErrorCode::Session(-3 | -13 | -16 | -37 | -43) => break,
                        _ => return Err(e.into()),
                    }
                } else if !out.is_empty() {
                    break;
                } else {
                    return Err(e.into());
                }
            }
        }
        if Instant::now() >= deadline { break; }
    }
    let _ = ch.wait_close();
    Ok(out)
}

// Function for building our SSH session and running our commands
fn run_cmd(ip: &str, user: &str, pass: &str, cmd: &str, vendor: Vendor) -> Result<String> {
    let tcp = connect_ssh(ip)?;
    let mut s = Session::new()?;

    s.set_tcp_stream(tcp);
    s.set_timeout(SSH_TIMEOUT_MS);
    s.handshake()?;
    s.userauth_password(user, pass)?;
    if !s.authenticated() { anyhow::bail!("auth rejected"); }

    let mut ch = s.channel_session()?;
    ch.request_pty("vt100", None, None)?;
    ch.shell()?;
    sleep(Duration::from_millis(150));

    /* ---- per-vendor pre/post commands ---- */
    let lines: Vec<&str> = match vendor {
        Vendor::Cisco   => vec!["terminal length 0", cmd, "exit"], // No "more" on the console output
        Vendor::Extreme => vec!["disable cli paging", cmd, "exit"],
        Vendor::Dell    => vec![cmd, "exit"],
        Vendor::Auto    => vec!["terminal length 0", cmd, "exit"],
    };

    for l in lines {
        ch.write_all(l.as_bytes())?;
        ch.write_all(b"\n")?;
    }

    ch.flush()?;
    ch.send_eof()?;
    read_all(ch)
}

// Hostname function, currently only has Cisco and Extreme switch support.
fn learn_hostname(ip: &str, u: &str, p: &str, vendor: Vendor) -> Option<String> {
    if vendor == Vendor::Extreme {
        if let Ok(sw) = run_cmd(ip, u, p, "show switch", Vendor::Extreme) {
            if let Some(c) = HOST_SYSNAME.captures(&sw) { return Some(c[1].trim().to_string()); }
        }
    }

    if vendor == Vendor::Cisco || vendor == Vendor::Auto {
        if let Ok(v) = run_cmd(ip, u, p, "show version", Vendor::Cisco) {
            if let Some(c) = HOST_VER.captures(&v) { return Some(c[1].trim().to_string()); }
        }
        if let Ok(r) = run_cmd(ip, u, p, "show running-config | include ^hostname", Vendor::Cisco) {
            if let Some(c) = HOST_RUN.captures(&r) { return Some(c[1].trim().to_string()); }
        }
        if let Ok(h) = run_cmd(ip, u, p, "show hostname", Vendor::Cisco) {
            if let Some(c) = HOST_SHHOST.captures(&h) { return Some(c[1].trim().to_string()); }
        }
    }
    None
}

/* ───── job struct ───── */
#[derive(Clone)]
struct Job { ip: String, hop: Option<String> }

#[allow(clippy::too_many_arguments)]
fn worker(
    rx: Receiver<Job>,
    tx_master: Sender<Job>,
    user: String,
    pass: String,
    names: Arc<DashMap<String, String>>,
    graph: Arc<Mutex<UGraph>>,
    node_of: Arc<DashMap<String, NodeIndex>>,
    good: Arc<DashMap<String, ()>>,
    queued: Arc<DashSet<String>>,
    aliases: Arc<DashMap<String, String>>,
    host: Arc<HostMap>,
    pending: Arc<AtomicUsize>,
    opts: Opts,
) {
    let tx = tx_master.clone();
    let cmds_v4 = ["show ip interface brief"];
    let cmds_v6 = ["show ipv6 interface brief"];

    loop {
        match rx.recv_timeout(WORKER_POLL) {
            Ok(job) => {
                let canon_ip = canon(&job.ip, &aliases);

                if !VISITED.insert(canon_ip.clone()) {
                    pending.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }

                // This is where I try to check the switch vendor but doesn't work yet
                // TODO:
                let ver_cmd = match opts.vendor {
                    Vendor::Extreme => "show switch",
                    Vendor::Dell    => "show system",
                    _               => "show version",
                };
                    // Run our commands and 
                if let Ok(ver) = run_cmd(&job.ip, &user, &pass, ver_cmd, opts.vendor) {
                    if matches!(opts.vendor, Vendor::Cisco)
                       || (opts.vendor == Vendor::Auto && is_ios(&ver)) {
                        if opts.vendor != Vendor::Cisco && !is_ios(&ver) {
                            pending.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                    }

                    let hostname = match learn_hostname(&job.ip, &user, &pass, opts.vendor) {
                        Some(h) => h,
                        None => {
                            good.insert(canon_ip.clone(), ());
                            pending.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                    };

                    SITE_PREFIX.get_or_init(|| site_of(&hostname).to_string());

                    good.insert(canon_ip.clone(), ());
                    names.insert(canon_ip.clone(), hostname.clone());
                    host.insert(hostname.clone(), canon_ip.clone());
                    aliases.insert(canon_addr(&job.ip), canon_ip.clone());

                    /* ─── graph node ─── */
                    let mut g = graph.lock().unwrap();
                    let me = *node_of.entry(canon_ip.clone()).or_insert_with(|| {
                        g.add_node(format!("{}\n{}", hostname, canon_ip))
                    });

                    if let Some(parent_raw) = &job.hop {
                        let parent = canon(parent_raw, &aliases);
                        if let Some(pidx) = node_of.get(&parent) {
                            g.update_edge(me, *pidx, 1);
                        }
                    }
                    drop(g);

                    /* ── gather own interface addresses ── */
                    for cmd in &cmds_v4 {
                        if let Ok(out) = run_cmd(&job.ip, &user, &pass, cmd, opts.vendor) {
                            for ip in extract_ips(&out, IpFamily::V4) {
                                aliases.insert(canon_addr(&ip), canon_ip.clone());
                            }
                            if !out.trim().is_empty() { break; }
                        }
                    }
                    for cmd in &cmds_v6 {
                        if let Ok(out) = run_cmd(&job.ip, &user, &pass, cmd, opts.vendor) {
                            for ip in extract_ips(&out, IpFamily::V6) {
                                aliases.insert(canon_addr(&ip), canon_ip.clone());
                            }
                            if !out.trim().is_empty() { break; }
                        }
                    }

                    /* ── neighbours ── */
                    let neighbour_cmds: &[&str] = match opts.vendor {
                        Vendor::Cisco | Vendor::Auto => &[
                            "show cdp neighbors detail",
                            "show lldp neighbors detail",
                        ],
                        Vendor::Extreme => &["show lldp neighbors detailed"],
                        Vendor::Dell    => &["show lldp neighbors detail"],
                    };

                    let mut out = String::new();
                    for cmd in neighbour_cmds {
                        out = run_cmd(&job.ip, &user, &pass, cmd, opts.vendor).unwrap_or_default();
                        if !out.trim().is_empty() { break; }
                    }

                    for (nbr_raw, nbr_host) in neighbours(&out, opts.fam) {
                        if nbr_host.is_empty() { continue; }

                        if opts.site_check {
                            let pref = SITE_PREFIX.get().unwrap();
                            if !site_of(&nbr_host).eq_ignore_ascii_case(pref) { continue; }
                        }

                        let nbr = host.get(&nbr_host).map(|ip| ip.value().clone())
                                      .unwrap_or_else(|| canon(&nbr_raw, &aliases));
                        aliases.insert(canon_addr(&nbr_raw), nbr.clone());

                        if queued.insert(nbr.clone()) {
                            pending.fetch_add(1, Ordering::SeqCst);
                            let _ = tx.send(Job { ip: nbr.clone(), hop: Some(canon_ip.clone()) });
                        } else if good.contains_key(&nbr) {
                            if let (Some(a), Some(b)) = (node_of.get(&nbr), node_of.get(&canon_ip)) {
                                let mut g = graph.lock().unwrap();
                                g.update_edge(*a, *b, 1);
                            }
                        }
                    }
                }
                pending.fetch_sub(1, Ordering::SeqCst);
            }

            Err(RecvTimeoutError::Timeout) if pending.load(Ordering::SeqCst) == 0 => break,
            Err(RecvTimeoutError::Disconnected) => break,
            _ => {},
        }
    }
}

/* ───── helper: add invisible ordering edges ───── */
fn add_ip_ordering_edges(g: &mut UGraph) {
    let mut v: Vec<(u32, NodeIndex)> = g.node_indices()
        .filter_map(|idx| {
            let ip = g[idx].rsplit('\n').next()?;
            ip_score(ip).map(|score| (score, idx))
        })
        .collect();
    v.sort_by_key(|t| t.0);
    for w in v.windows(2) {
        let (a, b) = (w[0].1, w[1].1);
        if g.find_edge(a, b).is_none() { g.add_edge(a, b, 0); }
    }
}

/* ───── PNG helper ───── */
fn render_png(orig: &UGraph, path: &Path) -> Result<()> {
    use petgraph::{
        dot::{Config, Dot},
        visit::EdgeRef,
        Directed, Graph,
    };
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn ip_key(ip: &str) -> Option<u128> {
        let mut parts = ip.split('.').map(|p| p.parse::<u128>().ok());
        let (o1, o2, o3, o4) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        Some((o1? << 96) | (o2? << 64) | (o3? << 32) | o4?)
    }

    fn directed_with_order(src: &UGraph) -> Graph<String, u8, Directed> {
        use petgraph::graph::{NodeIndex};
        let mut dst = Graph::<String, u8, Directed>::new();
        let mut map = Vec::with_capacity(src.node_count());

        for w in src.node_weights() { map.push(dst.add_node(w.clone())); }

        for e in src.edge_references() {
            let (a, b, w) = (e.source().index(), e.target().index(), *e.weight());
            if a < b { dst.add_edge(map[a], map[b], w); }
            else     { dst.add_edge(map[b], map[a], w); }
        }

        let mut vec: Vec<(u128, NodeIndex)> = dst.node_indices()
            .filter_map(|idx| {
                let ip = dst[idx].rsplit('\n').next().unwrap_or("");
                ip_key(ip).map(|k| (k, idx))
            })
            .collect();

        vec.sort_by_key(|t| t.0);
        for win in vec.windows(2) { dst.add_edge(win[0].1, win[1].1, 0); }

        dst
    }

    let dg = directed_with_order(orig);

    let dot = Dot::with_attr_getters(
        &dg,
        &[Config::EdgeNoLabel],
        &|_, e: petgraph::graph::EdgeReference<'_, u8>| -> String {
            if *e.weight() == 0 { r#"style="invis" weight="100" constraint="false" dir="none""#.into() }
            else                { r#"dir="none""#.into() }
        },
        &|_, (_idx, lbl): (petgraph::graph::NodeIndex, &String)| -> String {
            if let Some(pos) = lbl.find('\n') {
                let (host, ip) = lbl.split_at(pos);
                format!(
                    "label=<<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLPADDING=\"1\">\
                     <TR><TD><B>{}</B></TD></TR><TR><TD>{}</TD></TR></TABLE>>",
                     host, &ip[1..]
                )
            } else { format!("label=\"{}\"", lbl) }
        },
    );

    let mut tmp = NamedTempFile::new()?;
    write!(tmp, "{dot}")?;

    std::process::Command::new("dot")
        .args(["-Tpng", "-Grankdir=BT", tmp.path().to_str().unwrap(), "-o"])
        .arg(path)
        .status()?;

    Ok(())
}

/* ───── main ───── */
fn main() -> Result<()> {
    /* ---- CLI parsing ---------------------------------------------------- */
    let mut args = std::env::args();
    let _bin = args.next(); // skip argv[0]

    let seed = args.next()
        .expect("usage: netcrawler <seed_ip> [--vendor <cisco|extreme|dell|auto>]");

    // default = Auto (Cisco-first behaviour)
    let mut vendor = Vendor::Auto;
    while let Some(a) = args.next() {
        if a == "--vendor" {
            vendor = match args.next()
                .expect("--vendor requires an argument")
                .to_ascii_lowercase()
                .as_str()
            {
                "cisco"   => Vendor::Cisco,
                "extreme" => Vendor::Extreme,
                "dell"    => Vendor::Dell,
                "auto"    => Vendor::Auto,
                v         => panic!("unknown vendor \"{v}\""),
            };
        } else { panic!("unknown argument \"{a}\""); }
    }

    // Currently using environment variables. Might be better to ask the user on launch in a later release
    let user = std::env::var("NC_USER").expect("NC_USER missing");
    let pass = std::env::var("NC_PASS").expect("NC_PASS missing");

    // 
    let site_check = !matches!(std::env::var("NC_DISABLE_SITE_CHECK")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str(),
        "1" | "true" | "yes");

    let fam  = family_of(&seed);
    let opts = Opts { site_check, vendor, fam };

    /* ---- shared state --------------------------------------------------- */
    let graph   = Arc::new(Mutex::new(UGraph::new_undirected()));
    let node_of = Arc::new(DashMap::<String, NodeIndex>::new());
    let good    = Arc::new(DashMap::<String, ()>::new());
    let queued  = Arc::new(DashSet::<String>::new());
    let aliases = Arc::new(DashMap::<String, String>::new());
    let names   = Arc::new(DashMap::<String, String>::new());
    let host    = Arc::new(HostMap::new());

    let (tx, rx) = unbounded::<Job>();
    let pool     = ThreadPool::new(num_cpus::get());
    let pending  = Arc::new(AtomicUsize::new(1));

    queued.insert(seed.clone());
    aliases.insert(seed.clone(), seed.clone());
    tx.send(Job { ip: seed, hop: None }).unwrap();

    for _ in 0..pool.max_count() {
        let rx_c      = rx.clone();
        let tx_c      = tx.clone();
        let user_c    = user.clone();
        let pass_c    = pass.clone();
        let names_c   = names.clone();
        let graph_c   = graph.clone();
        let node_of_c = node_of.clone();
        let good_c    = good.clone();
        let queued_c  = queued.clone();
        let aliases_c = aliases.clone();
        let host_c    = host.clone();
        let pending_c = pending.clone();
        let opts_c    = opts;

        pool.execute(move || worker(
            rx_c, tx_c, user_c, pass_c, names_c, graph_c, node_of_c,
            good_c, queued_c, aliases_c, host_c, pending_c, opts_c,
        ));
    }
    drop(tx);
    pool.join();

    // Attempt to order the graphs in numerical order
    // Does not work as expected...
    // TODO:
    let mut g = graph.lock().unwrap();
    add_ip_ordering_edges(&mut g);

    // Report at the end how many switches we were able to find and connect to
    println!("switches discovered: {}", g.node_count());

    // Render the network topology graph
    render_png(&g, Path::new("topology.png"))?;

    // Done, exit status 0
    Ok(())
}

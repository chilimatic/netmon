//! Network interface discovery from /sys/class/net.

use std::{collections::HashMap, fs};

/// ARPHRD_ETHER and ARPHRD_LOOPBACK carry a 14-byte Ethernet header.
const ARPHRD_ETHER: u32 = 1;
const ARPHRD_LOOPBACK: u32 = 772;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iface {
    pub index: u32,
    pub name: String,
    /// Offset of the IP header in packets on this device.
    pub l3_offset: u32,
    pub kind: Kind,
}

/// What an interface is, for counting traffic once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Kind {
    /// Backed by hardware (or a VM's virtual NIC): traffic on the wire.
    Physical,
    /// A bridge: carries traffic of its ports again.
    Bridge,
    /// Linked to another interface (veth, vlan, macvlan): the same traffic
    /// also crosses that one.
    Peer,
    /// Loopback, tun/VPN and the rest.
    #[default]
    Other,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Physical => "physical",
            Kind::Bridge => "bridge",
            Kind::Peer => "veth/vlan",
            Kind::Other => "other",
        }
    }

    /// Rows of these interfaces repeat traffic seen elsewhere.
    pub fn is_virtual(self) -> bool {
        matches!(self, Kind::Bridge | Kind::Peer)
    }
}

/// Kind from sysfs facts: a `device` link, a `bridge` directory, and
/// `iflink` (the interface it is linked to) against `ifindex`.
fn kind(has_device: bool, is_bridge: bool, iflink: Option<u32>, index: u32) -> Kind {
    if has_device {
        Kind::Physical
    } else if is_bridge {
        Kind::Bridge
    } else if iflink.is_some_and(|l| l != index && l != 0) {
        Kind::Peer
    } else {
        Kind::Other
    }
}

/// Offset of the IP header for an ARPHRD device type. Devices without a
/// link-layer header (tun, wireguard, ppp) start at the IP header.
pub fn l3_offset(arphrd: u32) -> u32 {
    match arphrd {
        ARPHRD_ETHER | ARPHRD_LOOPBACK => 14,
        _ => 0,
    }
}

pub fn list() -> Vec<Iface> {
    let Ok(dir) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let read_u32 = |path: String| -> Option<u32> { fs::read_to_string(path).ok()?.trim().parse().ok() };
    let mut out: Vec<Iface> = dir
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let index = read_u32(format!("/sys/class/net/{name}/ifindex"))?;
            let ty = read_u32(format!("/sys/class/net/{name}/type")).unwrap_or(ARPHRD_ETHER);
            let base = format!("/sys/class/net/{name}");
            let kind = kind(
                fs::metadata(format!("{base}/device")).is_ok(),
                fs::metadata(format!("{base}/bridge")).is_ok(),
                read_u32(format!("{base}/iflink")),
                index,
            );
            Some(Iface { index, name, l3_offset: l3_offset(ty), kind })
        })
        .collect();
    out.sort_by_key(|i| i.index);
    out
}

/// ifindex -> name and kind, keeping interfaces that disappeared.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Names(HashMap<u32, (String, Kind)>);

impl Names {
    pub fn update(&mut self, ifaces: &[Iface]) {
        for i in ifaces {
            self.0.insert(i.index, (i.name.clone(), i.kind));
        }
    }

    pub fn get(&self, index: u32) -> String {
        self.0.get(&index).map(|(n, _)| n.clone()).unwrap_or_else(|| format!("if{index}"))
    }

    pub fn kind(&self, index: u32) -> Kind {
        self.0.get(&index).map(|(_, k)| *k).unwrap_or_default()
    }

    /// Interfaces whose traffic the totals count: the physical ones.
    pub fn physical(&self) -> std::collections::HashSet<u32> {
        self.0.iter().filter(|(_, (_, k))| *k == Kind::Physical).map(|(i, _)| *i).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_by_device_type() {
        assert_eq!(l3_offset(1), 14);
        assert_eq!(l3_offset(772), 14);
        assert_eq!(l3_offset(65534), 0); // tun / wireguard
    }

    #[test]
    fn lists_loopback() {
        let ifs = list();
        let lo = ifs.iter().find(|i| i.name == "lo").expect("lo exists");
        assert_eq!(lo.l3_offset, 14);
    }

    #[test]
    fn kinds() {
        assert_eq!(kind(true, false, Some(2), 2), Kind::Physical);
        assert_eq!(kind(false, true, Some(5), 5), Kind::Bridge);
        assert_eq!(kind(false, false, Some(2), 18), Kind::Peer, "veth: iflink is the peer");
        assert_eq!(kind(false, false, Some(7), 7), Kind::Other, "tun");
        assert_eq!(kind(false, false, Some(0), 9), Kind::Other);
        let lo = list().into_iter().find(|i| i.name == "lo").unwrap();
        assert_eq!(lo.kind, Kind::Other);
    }

    #[test]
    fn unknown_name_falls_back() {
        assert_eq!(Names::default().get(42), "if42");
    }
}

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
            Some(Iface { index, name, l3_offset: l3_offset(ty) })
        })
        .collect();
    out.sort_by_key(|i| i.index);
    out
}

/// ifindex -> name, keeping names of interfaces that disappeared.
#[derive(Default)]
pub struct Names(HashMap<u32, String>);

impl Names {
    pub fn update(&mut self, ifaces: &[Iface]) {
        for i in ifaces {
            self.0.insert(i.index, i.name.clone());
        }
    }

    pub fn get(&self, index: u32) -> String {
        self.0.get(&index).cloned().unwrap_or_else(|| format!("if{index}"))
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
    fn unknown_name_falls_back() {
        assert_eq!(Names::default().get(42), "if42");
    }
}

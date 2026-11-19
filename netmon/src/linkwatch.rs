//! Interface add/remove/rename events from rtnetlink (RTMGRP_LINK), so new
//! interfaces get the TC programs at once instead of at the next poll.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const RTMGRP_LINK: u32 = 1;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const NLMSG_HDRLEN: usize = 16;

pub struct LinkWatch {
    fd: OwnedFd,
}

impl LinkWatch {
    /// Opens a non-blocking rtnetlink socket subscribed to link events.
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain syscalls; the fd is owned right after creation.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_groups = RTMGRP_LINK;
            let len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            if libc::bind(fd.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(LinkWatch { fd })
        }
    }

    /// Reads every queued message. True if a link was added, removed or
    /// changed, or if events were lost (the caller then rescans anyway).
    pub fn changed(&self) -> bool {
        let mut buf = [0u8; 16384];
        let mut changed = false;
        loop {
            // SAFETY: buf is valid for buf.len() bytes.
            let n = unsafe {
                libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT)
            };
            if n > 0 {
                changed |= has_link_msg(&buf[..n as usize]);
                continue;
            }
            if n == 0 {
                return changed;
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) => return changed,
                Some(libc::EINTR) => continue,
                // ENOBUFS: the socket queue overflowed and events were lost.
                Some(libc::ENOBUFS) => changed = true,
                _ => return true,
            }
        }
    }
}

/// Does a netlink datagram hold an RTM_NEWLINK or RTM_DELLINK message?
fn has_link_msg(mut buf: &[u8]) -> bool {
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if ty == RTM_NEWLINK || ty == RTM_DELLINK {
            return true;
        }
        if len < NLMSG_HDRLEN {
            return false;
        }
        // Messages are 4-byte aligned.
        let next = (len + 3) & !3;
        if next >= buf.len() {
            return false;
        }
        buf = &buf[next..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(ty: u16, payload: usize) -> Vec<u8> {
        let len = (NLMSG_HDRLEN + payload) as u32;
        let mut m = Vec::new();
        m.extend_from_slice(&len.to_ne_bytes());
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(&[0u8; 10]);
        m.resize(((len as usize) + 3) & !3, 0);
        m
    }

    #[test]
    fn finds_link_messages() {
        assert!(has_link_msg(&msg(RTM_NEWLINK, 16)));
        assert!(has_link_msg(&msg(RTM_DELLINK, 0)));
        // RTM_NEWADDR (20) then RTM_NEWLINK with an unaligned length.
        let mut two = msg(20, 5);
        two.extend(msg(RTM_NEWLINK, 3));
        assert!(has_link_msg(&two));
        assert!(!has_link_msg(&msg(20, 8)));
    }

    #[test]
    fn malformed_input_stops() {
        assert!(!has_link_msg(&[]));
        assert!(!has_link_msg(&[1, 2, 3]));
        // Length 0 would loop forever without the check.
        let mut zero = msg(20, 0);
        zero[0..4].copy_from_slice(&0u32.to_ne_bytes());
        zero.extend(msg(RTM_NEWLINK, 0));
        assert!(!has_link_msg(&zero));
    }

    #[test]
    fn opens_without_root() {
        let w = LinkWatch::open().expect("rtnetlink link group needs no privilege");
        let _ = w.changed();
    }
}

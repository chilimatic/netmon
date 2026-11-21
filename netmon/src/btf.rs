//! A small reader for the kernel's BTF (/sys/kernel/btf/vmlinux): byte
//! offsets of struct members. The eBPF programs get these offsets in a
//! config map and read kernel structs with them. aya gives no stable CO-RE
//! for this, and its BTF types keep the members private.

use std::collections::HashMap;

const MAGIC: u16 = 0xeb9f;
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

struct Member {
    name: u32,
    ty: u32,
    /// Offset in bits.
    bits: u32,
}

struct Type {
    name: u32,
    kind: u32,
    /// Referenced type (typedef, const, ...), unused for structs.
    ty: u32,
    members: Vec<Member>,
}

pub struct Btf {
    /// Index = type id - 1.
    types: Vec<Type>,
    strings: Vec<u8>,
    structs: HashMap<String, u32>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

impl Btf {
    pub fn from_sys_fs() -> Result<Self, String> {
        let data = std::fs::read("/sys/kernel/btf/vmlinux").map_err(|e| format!("read /sys/kernel/btf/vmlinux: {e}"))?;
        Self::parse(&data).ok_or_else(|| "kernel BTF: unexpected format".to_string())
    }

    /// Parses little-endian BTF. None on any format error.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if u16_at(b, 0)? != MAGIC {
            return None;
        }
        let hdr = u32_at(b, 4)? as usize;
        let (type_off, type_len) = (u32_at(b, 8)? as usize, u32_at(b, 12)? as usize);
        let (str_off, str_len) = (u32_at(b, 16)? as usize, u32_at(b, 20)? as usize);
        let tb = b.get(hdr + type_off..hdr + type_off + type_len)?;
        let strings = b.get(hdr + str_off..hdr + str_off + str_len)?.to_vec();
        let mut types = Vec::new();
        let mut o = 0;
        while o < tb.len() {
            let name = u32_at(tb, o)?;
            let info = u32_at(tb, o + 4)?;
            let ty = u32_at(tb, o + 8)?;
            o += 12;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let bitfield = info >> 31 != 0;
            let mut members = Vec::new();
            match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => o += 4,
                KIND_ARRAY => o += 12,
                KIND_STRUCT | KIND_UNION => {
                    for _ in 0..vlen {
                        let off = u32_at(tb, o + 8)?;
                        let bits = if bitfield { off & 0xff_ffff } else { off };
                        members.push(Member { name: u32_at(tb, o)?, ty: u32_at(tb, o + 4)?, bits });
                        o += 12;
                    }
                }
                KIND_ENUM | KIND_FUNC_PROTO => o += 8 * vlen,
                KIND_DATASEC | KIND_ENUM64 => o += 12 * vlen,
                // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC,
                // FLOAT, TYPE_TAG: no extra data.
                2 | 7 | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | 12 | 16 | KIND_TYPE_TAG => {}
                _ => return None,
            }
            types.push(Type { name, kind, ty, members });
        }
        let mut btf = Btf { types, strings, structs: HashMap::new() };
        for (i, t) in btf.types.iter().enumerate() {
            if t.kind == KIND_STRUCT && t.name != 0 {
                btf.structs.entry(btf.name(t.name).to_string()).or_insert(i as u32 + 1);
            }
        }
        Some(btf)
    }

    fn name(&self, off: u32) -> &str {
        let rest = self.strings.get(off as usize..).unwrap_or_default();
        let end = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).unwrap_or("")
    }

    fn ty(&self, id: u32) -> Option<&Type> {
        self.types.get((id as usize).checked_sub(1)?)
    }

    /// Follows typedef, const, volatile, restrict and type tags.
    fn resolve(&self, mut id: u32) -> Option<&Type> {
        for _ in 0..32 {
            let t = self.ty(id)?;
            match t.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => id = t.ty,
                _ => return Some(t),
            }
        }
        None
    }

    /// Byte offset of `member` in struct `name`. Looks into anonymous
    /// structs and unions too: many kernel fields sit in one.
    pub fn offset(&self, name: &str, member: &str) -> Option<u32> {
        let t = self.ty(*self.structs.get(name)?)?;
        self.find(t, member, 0).map(|bits| bits / 8)
    }

    fn find(&self, t: &Type, member: &str, depth: u32) -> Option<u32> {
        if depth > 8 {
            return None;
        }
        for m in &t.members {
            if m.name != 0 && self.name(m.name) == member {
                return Some(m.bits);
            }
        }
        for m in t.members.iter().filter(|m| m.name == 0) {
            if let Some(inner) = self.resolve(m.ty)
                && (inner.kind == KIND_STRUCT || inner.kind == KIND_UNION)
                && let Some(b) = self.find(inner, member, depth + 1)
            {
                return Some(m.bits + b);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BTF with: 1 int, 2 struct inner { int x @ 32 bits }, 3 struct outer
    /// { int a @ 0; anonymous inner @ 64 }, 4 typedef of 2.
    fn sample() -> Vec<u8> {
        let strings = b"\0int\0inner\0x\0outer\0a\0t\0".to_vec();
        let s = |name: &str| strings.windows(name.len() + 1).position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0).unwrap() as u32;
        let mut t = Vec::new();
        let mut push = |vals: &[u32]| vals.iter().for_each(|v| t.extend_from_slice(&v.to_le_bytes()));
        push(&[s("int"), KIND_INT << 24, 4, 32]);
        push(&[s("inner"), KIND_STRUCT << 24 | 1, 8, s("x"), 1, 32]);
        push(&[s("outer"), KIND_STRUCT << 24 | 2, 16, s("a"), 1, 0, 0, 4, 64]);
        push(&[s("t"), KIND_TYPEDEF << 24, 2]);
        let mut b = Vec::new();
        b.extend_from_slice(&MAGIC.to_le_bytes());
        b.extend_from_slice(&[1, 0]);
        for v in [24u32, 0, t.len() as u32, t.len() as u32, strings.len() as u32] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&t);
        b.extend_from_slice(&strings);
        b
    }

    #[test]
    fn member_offsets_also_in_anonymous_members() {
        let btf = Btf::parse(&sample()).unwrap();
        assert_eq!(btf.offset("inner", "x"), Some(4));
        assert_eq!(btf.offset("outer", "a"), Some(0));
        assert_eq!(btf.offset("outer", "x"), Some(12), "8 bytes to the anonymous member, 4 inside it");
        assert_eq!(btf.offset("outer", "y"), None);
        assert_eq!(btf.offset("nothing", "x"), None);
        assert!(Btf::parse(&[0u8; 24]).is_none(), "bad magic");
    }

    #[test]
    fn kernel_btf_has_the_exe_path() {
        let Ok(btf) = Btf::from_sys_fs() else { return };
        for (s, m) in [("task_struct", "mm"), ("mm_struct", "exe_file"), ("file", "f_inode"), ("inode", "i_ino"), ("inode", "i_sb"), ("super_block", "s_dev")] {
            assert!(btf.offset(s, m).is_some(), "{s}.{m}");
        }
    }
}

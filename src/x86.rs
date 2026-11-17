//! A deliberately narrow x86-64 decoder.
//!
//! The kernel only trusts instructions it can decode itself. This is not a
//! general disassembler: it covers the scalar/SSE load-store and small integer
//! idioms DeG's built-in evidence needs (`loads`, `stores`, and `modulo`).
//! Anything outside the subset makes the evidence *partial* and caps it at
//! `Heuristic`; a full disassembler can still emit an external certificate, but
//! that certificate is capped at `Observational`.
//!
//! Address-space and ABI assumptions (which register holds the struct base) are
//! rule-library assumptions, documented in `docs/semantics.md`; the bytes
//! themselves are checked deterministically.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemOperand {
    pub base: Option<u8>,
    pub index: Option<u8>,
    pub scale: u8,
    pub disp: i64,
    pub width: u8,
    pub write: bool,
    pub rip_relative: bool,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: u64,
    pub len: usize,
    pub mnemonic: String,
    pub mem: Option<MemOperand>,
    pub imm: Option<i64>,
    /// For `mov reg, imm`: destination register number (0 = rax, 1 = rcx, ...).
    pub mov_reg: Option<u8>,
    /// For `div reg` / `idiv reg`: divisor register.
    pub div_reg: Option<u8>,
    pub is_ret: bool,
}

#[derive(Debug, Clone)]
pub struct Decode {
    pub insns: Vec<Insn>,
    pub complete: bool,
    pub bytes_consumed: usize,
    pub stop_reason: Option<String>,
}

pub fn decode(bytes: &[u8], base_addr: u64, max_insns: usize) -> Decode {
    let mut insns = Vec::new();
    let mut pos = 0usize;
    while insns.len() < max_insns {
        if pos >= bytes.len() {
            return Decode {
                insns,
                complete: false,
                bytes_consumed: pos,
                stop_reason: Some("ran out of bytes".into()),
            };
        }
        let start = pos;
        match decode_one(bytes, pos, base_addr + pos as u64) {
            Ok((insn, next)) => {
                pos = next;
                let is_ret = insn.is_ret;
                insns.push(insn);
                if is_ret {
                    return Decode {
                        insns,
                        complete: true,
                        bytes_consumed: pos,
                        stop_reason: None,
                    };
                }
            }
            Err(e) => {
                return Decode {
                    insns,
                    complete: false,
                    bytes_consumed: start,
                    stop_reason: Some(e),
                };
            }
        }
    }
    Decode {
        insns,
        complete: true,
        bytes_consumed: pos,
        stop_reason: None,
    }
}

fn decode_one(bytes: &[u8], start: usize, addr: u64) -> Result<(Insn, usize), String> {
    let mut pos = start;
    let mut rex_w = false;
    let mut rex_b = false;
    let mut pf3 = false;
    let mut pf2 = false;

    // Prefixes. Bound the loop so a malformed stream cannot spin.
    for _ in 0..4 {
        let b = *bytes.get(pos).ok_or("truncated prefix")?;
        match b {
            0x66 => {
                pos += 1;
            }
            0xF3 => {
                pf3 = true;
                pos += 1;
            }
            0xF2 => {
                pf2 = true;
                pos += 1;
            }
            0x40..=0x4F => {
                rex_w = b & 0x08 != 0;
                rex_b = b & 0x01 != 0;
                pos += 1;
            }
            _ => break,
        }
    }

    let op = *bytes.get(pos).ok_or("truncated opcode")?;
    pos += 1;

    let mk = |mnemonic: &str,
              len: usize,
              mem: Option<MemOperand>,
              imm: Option<i64>,
              mov_reg: Option<u8>,
              div_reg: Option<u8>,
              is_ret: bool| {
        Insn {
            addr,
            len,
            mnemonic: mnemonic.to_string(),
            mem,
            imm,
            mov_reg,
            div_reg,
            is_ret,
        }
    };

    // Two-byte opcodes.
    if op == 0x0F {
        let op2 = *bytes.get(pos).ok_or("truncated two-byte opcode")?;
        pos += 1;
        match op2 {
            // endbr64 / endbr32
            0x1E if pf3 => {
                let modrm = *bytes.get(pos).ok_or("truncated endbr")?;
                if modrm == 0xFA || modrm == 0xFB {
                    pos += 1;
                    return Ok((mk("endbr", pos - start, None, None, None, None, false), pos));
                }
                return Err(format!("unsupported F3 0F 1E {modrm:02x}"));
            }
            // nop r/m (0F 1F /0)
            0x1F => {
                let (m, len) = modrm(bytes, pos, rex_b, 0, false)?;
                pos += len;
                return Ok((mk("nop", pos - start, m, None, None, None, false), pos));
            }
            // syscall
            0x05 => {
                return Ok((
                    mk("syscall", pos - start, None, None, None, None, false),
                    pos,
                ))
            }
            // Moves and arithmetic with SSE operands.
            0x10 | 0x11 | 0x28 | 0x29 | 0x58 | 0x59 | 0x5C | 0x5D | 0x5E | 0x5F => {
                let width = if pf3 {
                    4
                } else if pf2 {
                    8
                } else {
                    16
                };
                let write = op2 == 0x11 || op2 == 0x29;
                let (m, len) = modrm(bytes, pos, rex_b, width, write)?;
                pos += len;
                let mnemonic = match op2 {
                    0x10 => "movs",
                    0x11 => "movs.store",
                    0x28 => "movaps",
                    0x29 => "movaps.store",
                    0x58 => "adds",
                    0x59 => "muls",
                    0x5C => "subs",
                    0x5D => "mins",
                    0x5E => "divs",
                    0x5F => "maxs",
                    _ => "sse",
                };
                return Ok((mk(mnemonic, pos - start, m, None, None, None, false), pos));
            }
            // jcc rel32
            0x84 | 0x85 => {
                let imm = read_i32(bytes, pos)?;
                pos += 4;
                return Ok((
                    mk(
                        "jcc",
                        pos - start,
                        None,
                        Some(imm as i64),
                        None,
                        None,
                        false,
                    ),
                    pos,
                ));
            }
            _ => return Err(format!("unsupported 0F {op2:02x}")),
        }
    }

    match op {
        // mov r32/r64, r/m
        0x8B => {
            let width = if rex_w { 8 } else { 4 };
            let (m, len) = modrm(bytes, pos, rex_b, width, false)?;
            pos += len;
            Ok((mk("mov", pos - start, m, None, None, None, false), pos))
        }
        // mov r/m, r32/r64
        0x89 => {
            let width = if rex_w { 8 } else { 4 };
            let (m, len) = modrm(bytes, pos, rex_b, width, true)?;
            pos += len;
            Ok((
                mk("mov.store", pos - start, m, None, None, None, false),
                pos,
            ))
        }
        // lea r, m (no memory access)
        0x8D => {
            let (_, len) = modrm_raw(bytes, pos, rex_b)?;
            pos += len;
            Ok((mk("lea", pos - start, None, None, None, None, false), pos))
        }
        // mov reg, imm32 / imm64
        0xB8..=0xBF => {
            let reg = (op - 0xB8) | if rex_b { 8 } else { 0 };
            if rex_w {
                let imm = read_i64(bytes, pos)?;
                pos += 8;
                Ok((
                    mk("mov", pos - start, None, Some(imm), Some(reg), None, false),
                    pos,
                ))
            } else {
                let imm = read_i32(bytes, pos)?;
                pos += 4;
                Ok((
                    mk(
                        "mov",
                        pos - start,
                        None,
                        Some(imm as i64),
                        Some(reg),
                        None,
                        false,
                    ),
                    pos,
                ))
            }
        }
        // xor r/m, r
        0x31 => {
            let (m, len) = modrm(bytes, pos, rex_b, 4, true)?;
            pos += len;
            Ok((mk("xor", pos - start, m, None, None, None, false), pos))
        }
        // div / idiv r/m32
        0xF7 => {
            let mbyte = *bytes.get(pos).ok_or("truncated F7")?;
            let modbits = (mbyte >> 6) & 3;
            let reg = (mbyte >> 3) & 7;
            let rm = (mbyte & 7) | if rex_b { 8 } else { 0 };
            if modbits == 3 && (reg == 6 || reg == 7) {
                pos += 1;
                let div_reg = Some(rm);
                return Ok((
                    mk("div", pos - start, None, None, None, div_reg, false),
                    pos,
                ));
            }
            let (m, len) = modrm(bytes, pos, rex_b, 4, false)?;
            pos += len;
            Ok((mk("f7", pos - start, m, None, None, None, false), pos))
        }
        // add/sub with imm8 / imm32 (common prologue arithmetic)
        0x83 | 0x81 => {
            let (m, len) = modrm(bytes, pos, rex_b, if rex_w { 8 } else { 4 }, true)?;
            pos += len;
            if op == 0x83 {
                if pos >= bytes.len() {
                    return Err("truncated imm8".into());
                }
                pos += 1;
            } else {
                pos += 4;
            }
            Ok((
                mk("arithmetic", pos - start, m, None, None, None, false),
                pos,
            ))
        }
        // mov r/m, imm32 (/0)
        0xC7 => {
            let mbyte = *bytes.get(pos).ok_or("truncated C7")?;
            let reg = (mbyte >> 3) & 7;
            if reg != 0 {
                return Err(format!("unsupported C7 /{reg}"));
            }
            let (m, len) = modrm(bytes, pos, rex_b, 4, true)?;
            pos += len;
            let imm = read_i32(bytes, pos)?;
            pos += 4;
            Ok((
                mk("mov", pos - start, m, Some(imm as i64), None, None, false),
                pos,
            ))
        }
        // nop, ret, int3
        0x90 => Ok((mk("nop", pos - start, None, None, None, None, false), pos)),
        0xC3 => Ok((mk("ret", pos - start, None, None, None, None, true), pos)),
        0xCC => Ok((mk("int3", pos - start, None, None, None, None, false), pos)),
        // push/pop rbp, leave
        0x55 => Ok((mk("push", pos - start, None, None, None, None, false), pos)),
        0x5D => Ok((mk("pop", pos - start, None, None, None, None, false), pos)),
        0xC9 => Ok((mk("leave", pos - start, None, None, None, None, false), pos)),
        // call/jmp rel32
        0xE8 => {
            pos += 4;
            Ok((mk("call", pos - start, None, None, None, None, false), pos))
        }
        0xE9 => {
            pos += 4;
            Ok((mk("jmp", pos - start, None, None, None, None, false), pos))
        }
        0xEB => {
            pos += 1;
            Ok((mk("jmp", pos - start, None, None, None, None, false), pos))
        }
        // jcc rel8
        0x70..=0x7F => {
            pos += 1;
            Ok((mk("jcc", pos - start, None, None, None, None, false), pos))
        }
        _ => Err(format!("unsupported opcode {op:02x}")),
    }
}

/// Decode a ModR/M operand. Returns the memory operand (if any) and bytes used.
fn modrm(
    bytes: &[u8],
    pos: usize,
    rex_b: bool,
    width: u8,
    write: bool,
) -> Result<(Option<MemOperand>, usize), String> {
    let (mem, len) = modrm_raw(bytes, pos, rex_b)?;
    Ok((mem.map(|m| MemOperand { width, write, ..m }), len))
}

fn modrm_raw(bytes: &[u8], pos: usize, rex_b: bool) -> Result<(Option<MemOperand>, usize), String> {
    let mbyte = *bytes.get(pos).ok_or("truncated modrm")?;
    let modbits = (mbyte >> 6) & 3;
    let rm = (mbyte & 7) | if rex_b { 8 } else { 0 };
    let mut used = 1usize;
    if modbits == 3 {
        return Ok((None, used));
    }

    let mut base = Some(rm);
    let mut index = None;
    let mut scale = 1u8;
    let mut disp = 0i64;
    let mut rip_relative = false;

    if rm & 7 == 4 {
        // SIB byte.
        let sib = *bytes.get(pos + used).ok_or("truncated sib")?;
        used += 1;
        let scale_bits = sib >> 6;
        scale = 1 << scale_bits;
        let idx = (sib >> 3) & 7;
        let base_bits = sib & 7;
        if idx == 4 {
            index = None;
        } else {
            index = Some(idx);
        }
        if base_bits == 5 && modbits == 0 {
            base = None;
            disp = read_i32(bytes, pos + used)? as i64;
            used += 4;
        } else {
            base = Some(base_bits | if rex_b { 8 } else { 0 });
        }
    }

    match modbits {
        0 => {
            if rm & 7 == 5 {
                // RIP-relative.
                rip_relative = true;
                base = None;
                disp = read_i32(bytes, pos + used)? as i64;
                used += 4;
            }
        }
        1 => {
            let d = *bytes.get(pos + used).ok_or("truncated disp8")?;
            disp = (d as i8) as i64;
            used += 1;
        }
        2 => {
            disp = read_i32(bytes, pos + used)? as i64;
            used += 4;
        }
        _ => unreachable!(),
    }

    Ok((
        Some(MemOperand {
            base,
            index,
            scale,
            disp,
            width: 0,
            write: false,
            rip_relative,
        }),
        used,
    ))
}

fn read_i32(bytes: &[u8], pos: usize) -> Result<i32, String> {
    let slice = bytes
        .get(pos..pos + 4)
        .ok_or("truncated 32-bit immediate")?;
    Ok(i32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_i64(bytes: &[u8], pos: usize) -> Result<i64, String> {
    let slice = bytes
        .get(pos..pos + 8)
        .ok_or("truncated 64-bit immediate")?;
    Ok(i64::from_le_bytes(slice.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_fixture_reader() {
        let code = [
            0x48, 0xB8, 0x44, 0x65, 0x47, 0x21, 0x62, 0x31, 0x00, 0x00, // mov rax, imm64
            0xF3, 0x0F, 0x10, 0x47, 0x08, // movss xmm0, [rdi+8]
            0xF3, 0x0F, 0x10, 0x47, 0x04, // movss xmm1, [rdi+4]
            0xF3, 0x0F, 0x10, 0x47, 0x00, // movss xmm2, [rdi+0]
            0xC3, // ret
        ];
        let d = decode(&code, 0x140001000, 16);
        assert!(d.complete);
        assert_eq!(d.insns.len(), 5);
        let loads: Vec<(i64, u8)> = d
            .insns
            .iter()
            .filter_map(|i| {
                i.mem
                    .as_ref()
                    .filter(|m| !m.write)
                    .map(|m| (m.disp, m.width))
            })
            .collect();
        assert_eq!(loads, vec![(8, 4), (4, 4), (0, 4)]);
    }

    #[test]
    fn decodes_modulo_idiom() {
        let code = [
            0xB9, 0x0C, 0x00, 0x00, 0x00, // mov ecx, 12
            0x31, 0xD2, // xor edx, edx
            0xF7, 0xF1, // div ecx
            0xC3,
        ];
        let d = decode(&code, 0x140001100, 16);
        assert!(d.complete);
        assert_eq!(d.insns[0].mov_reg, Some(1));
        assert_eq!(d.insns[0].imm, Some(12));
        assert_eq!(d.insns[2].div_reg, Some(1));
    }

    #[test]
    fn partial_decode_is_not_silently_complete() {
        let d = decode(&[0xA5, 0xA5], 0, 4);
        assert!(!d.complete);
        assert!(d.insns.is_empty());
    }

    #[test]
    fn decodes_sse_stores_and_lea() {
        let code = [
            0x48, 0x8D, 0x4F, 0x10, // lea rcx, [rdi+16]
            0xF3, 0x0F, 0x11, 0x4F, 0x04, // movss [rdi+4], xmm1
            0xC3,
        ];
        let d = decode(&code, 0, 8);
        assert!(d.complete);
        assert!(d.insns[0].mem.is_none());
        let store = d.insns[1].mem.as_ref().unwrap();
        assert!(store.write);
        assert_eq!(store.disp, 4);
    }
}

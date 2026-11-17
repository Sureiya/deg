//! Minimal PE32/PE32+ image parser for build artifacts.
//!
//! DeG models address binaries by *virtual address*. For raw images the model
//! declares an explicit load base; for PE images (`build … format: pe`) the
//! section table is parsed here so virtual addresses can be mapped back to
//! file offsets through the section headers — no external dependencies.
//!
//! The public address model is the **image-base virtual address**: every
//! address this module accepts or returns is `image_base + RVA`, exactly the
//! addresses seen in disassemblers and reverse-engineering references. The
//! section headers store RVAs, which live on `Section.rva`; nothing public
//! deals in bare RVAs.
//!
//! The parser reads only what the kernel needs:
//!
//! * DOS header `e_lfanew` (file offset of the PE signature);
//! * the `PE\0\0` signature;
//! * the COFF header (number of sections, size of the optional header);
//! * the optional header (magic, image base, section alignment);
//! * the 40-byte section table entries.
//!
//! Anything else in the image is treated as opaque bytes.

/// Section is executable.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section is readable.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Section is writable.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// Section contains executable code.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// Section contains initialized data.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// Section contains uninitialized data.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;

/// One entry of the PE section table.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (e.g. `.text`), NUL-stripped.
    pub name: String,
    /// RVA (relative virtual address) of the section, relative to the image
    /// base. Use `image_base + rva` for an image-base virtual address.
    pub rva: u64,
    /// Size of the section when mapped in memory.
    pub virtual_size: u64,
    /// File offset of the section's raw data.
    pub raw_offset: u64,
    /// Size of the section's raw data in the file.
    pub raw_size: u64,
    /// `IMAGE_SCN_*` characteristics bits.
    pub characteristics: u32,
}

impl Section {
    /// The addressable size of the section: `virtual_size` when declared,
    /// otherwise the raw size (some linkers leave it zero).
    pub fn size(&self) -> u64 {
        if self.virtual_size > 0 {
            self.virtual_size
        } else {
            self.raw_size
        }
    }
}

/// A parsed PE image: just enough header information to map virtual
/// addresses to file offsets and to find sections by name.
#[derive(Debug, Clone)]
pub struct PeImage {
    pub sections: Vec<Section>,
    pub image_base: u64,
    pub is_pe32: bool,
    /// Length of the file the image was parsed from (for bounds checks).
    file_len: usize,
}

impl PeImage {
    /// Map an image-base virtual address to a file offset, or `None` when the
    /// address is below the image base, outside every section, or outside the
    /// file.
    pub fn va_to_file(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        let s = self.sections.iter().find(|s| {
            let size = s.size();
            rva >= s.rva && rva < s.rva + size
        })?;
        let off = s.raw_offset as usize + (rva - s.rva) as usize;
        (off < self.file_len).then_some(off)
    }

    /// Index of the section containing a virtual address, or `None` when the
    /// address is below the image base or outside every section.
    pub fn section_index_of(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        self.sections.iter().position(|s| {
            let size = s.size();
            rva >= s.rva && rva < s.rva + size
        })
    }

    /// Look a section up by name, case-insensitively (`.TEXT` and `.text` are
    /// the same section).
    pub fn section(&self, name: &str) -> Option<&Section> {
        let name = name.trim();
        self.sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// The image-base virtual range of a named section, or `None` when the
    /// section does not exist.
    pub fn section_range(&self, name: &str) -> Option<(u64, u64)> {
        let sec = self.section(name)?;
        Some((
            self.image_base + sec.rva,
            self.image_base + sec.rva + sec.size(),
        ))
    }

    /// The image-base virtual range of the executable code: the section named
    /// `.text` when present, otherwise the first section with
    /// `IMAGE_SCN_MEM_EXECUTE`.
    pub fn executable_range(&self) -> Option<(u64, u64)> {
        let sec = self.section(".text").or_else(|| {
            self.sections
                .iter()
                .find(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        })?;
        Some((
            self.image_base + sec.rva,
            self.image_base + sec.rva + sec.size(),
        ))
    }
}

/// Parse a PE image from file bytes.
pub fn parse(bytes: &[u8]) -> Result<PeImage, String> {
    if bytes.len() < 0x40 {
        return Err(format!(
            "PE image too small ({} bytes); no room for a DOS header",
            bytes.len()
        ));
    }
    if &bytes[0..2] != b"MZ" {
        return Err("not a PE image: missing DOS `MZ` magic".to_string());
    }
    let e_lfanew = rd_u32(bytes, 0x3C, "DOS header")? as usize;
    if e_lfanew + 24 > bytes.len() {
        return Err("truncated PE image: headers run past the end of the file".to_string());
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(format!(
            "not a PE image: missing `PE\\0\\0` signature at file offset {e_lfanew:#x}"
        ));
    }
    let coff = e_lfanew + 4;
    // Machine (2 bytes, unvalidated: any PE target is fine for address mapping).
    let _machine = rd_u16(bytes, coff, "COFF header")?;
    let num_sections = rd_u16(bytes, coff + 2, "COFF header")? as usize;
    let opt_size = rd_u16(bytes, coff + 16, "COFF header")? as usize;
    if num_sections == 0 || num_sections > 96 {
        return Err(format!("implausible PE section count {num_sections}"));
    }
    let opt = coff + 20;
    if opt + 40 > bytes.len() {
        return Err(
            "truncated PE image: optional header runs past the end of the file".to_string(),
        );
    }
    let magic = rd_u16(bytes, opt, "optional header")?;
    let is_pe32 = match magic {
        0x10B => true,
        0x20B => false,
        other => {
            return Err(format!(
                "unsupported PE optional-header magic {other:#06x} (expected 0x10B PE32 or 0x20B PE32+)"
            ))
        }
    };
    // PE32 stores ImageBase as a 4-byte DWORD at +28; PE32+ stores it as an
    // 8-byte field at +24. SectionAlignment is at +32 in both layouts.
    let image_base = if is_pe32 {
        rd_u32(bytes, opt + 28, "optional header")? as u64
    } else {
        rd_u64(bytes, opt + 24, "optional header")?
    };
    let _section_alignment = rd_u32(bytes, opt + 32, "optional header")?;

    let mut sections = Vec::with_capacity(num_sections);
    let mut entry = opt + opt_size;
    for i in 0..num_sections {
        if entry + 40 > bytes.len() {
            return Err(format!(
                "truncated PE image: section table runs past the end of the file (section {i} of {num_sections})"
            ));
        }
        let name_raw = &bytes[entry..entry + 8];
        let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..name_len]).to_string();
        sections.push(Section {
            name,
            virtual_size: rd_u32(bytes, entry + 8, "section header")? as u64,
            rva: rd_u32(bytes, entry + 12, "section header")? as u64,
            raw_size: rd_u32(bytes, entry + 16, "section header")? as u64,
            raw_offset: rd_u32(bytes, entry + 20, "section header")? as u64,
            characteristics: rd_u32(bytes, entry + 36, "section header")?,
        });
        entry += 40;
    }

    Ok(PeImage {
        sections,
        image_base,
        is_pe32,
        file_len: bytes.len(),
    })
}

fn rd_u16(bytes: &[u8], off: usize, what: &str) -> Result<u16, String> {
    bytes
        .get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("truncated PE image reading {what} at file offset {off:#x}"))
}

fn rd_u32(bytes: &[u8], off: usize, what: &str) -> Result<u32, String> {
    bytes
        .get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("truncated PE image reading {what} at file offset {off:#x}"))
}

fn rd_u64(bytes: &[u8], off: usize, what: &str) -> Result<u64, String> {
    bytes
        .get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| format!("truncated PE image reading {what} at file offset {off:#x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic PE32 image in memory:
    ///
    /// * image base 0x400000;
    /// * `.text`  RVA 0x1000 (VA 0x401000), raw at 0x200, 0x200 bytes
    ///   (executable);
    /// * `.rdata` RVA 0x2000 (VA 0x402000), raw at 0x400, 0x200 bytes of raw
    ///   data of which 0x100 are mapped.
    ///
    /// The file is 0x600 bytes: 0x200 of headers, then the two sections.
    fn synthetic_pe32() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        // DOS header.
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature + COFF header.
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x14Cu16.to_le_bytes()); // Machine: i386
        bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
        bytes[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
                                                                               // Optional header (PE32).
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes()); // Magic: PE32
        bytes[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase (DWORD)
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
                                                                            // Section table.
        let table = opt + 0xE0;
        // .text
        bytes[table..table + 8].copy_from_slice(b".text\0\0\0");
        bytes[table + 8..table + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        bytes[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        bytes[table + 16..table + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        bytes[table + 20..table + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        bytes[table + 36..table + 40].copy_from_slice(
            &(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes(),
        );
        // .rdata
        bytes[table + 40..table + 48].copy_from_slice(b".rdata\0\0");
        bytes[table + 48..table + 52].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        bytes[table + 52..table + 56].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        bytes[table + 56..table + 60].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        bytes[table + 60..table + 64].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        bytes[table + 76..table + 80]
            .copy_from_slice(&(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ).to_le_bytes());
        // Section bytes: .text is NOPs, .rdata starts with a known marker.
        bytes[0x200..0x400].fill(0x90);
        bytes[0x400..0x405].copy_from_slice(b"ABCDE");
        bytes
    }

    #[test]
    fn parses_headers_and_sections() {
        let image = parse(&synthetic_pe32()).unwrap();
        assert_eq!(image.image_base, 0x400000);
        assert!(image.is_pe32);
        assert_eq!(image.sections.len(), 2);
        assert_eq!(image.sections[0].name, ".text");
        assert_eq!(image.sections[0].rva, 0x1000);
        assert_eq!(image.sections[1].name, ".rdata");
        assert_eq!(
            image.sections[1].characteristics,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        );
    }

    #[test]
    fn maps_image_base_virtual_addresses_through_sections() {
        let image = parse(&synthetic_pe32()).unwrap();
        // .text: VA 0x401000 -> file 0x200.
        assert_eq!(image.va_to_file(0x401000), Some(0x200));
        assert_eq!(image.va_to_file(0x401004), Some(0x204));
        // .rdata: VA 0x402000 -> file 0x400, limited to its 0x100 mapped size.
        assert_eq!(image.va_to_file(0x402000), Some(0x400));
        assert_eq!(image.va_to_file(0x4020FF), Some(0x4FF));
        // A bare RVA below the image base is not addressable.
        assert_eq!(image.va_to_file(0x2000), None);
        // The gap between the sections is unmapped.
        assert_eq!(image.va_to_file(0x401FFF), None);
        // Past the mapped size of .rdata.
        assert_eq!(image.va_to_file(0x402100), None);
        // .rdata raw data beyond the mapped size is not addressable.
        assert_eq!(image.va_to_file(0x402200), None);
        // Past the end of the last section.
        assert_eq!(image.va_to_file(0x405000), None);
    }

    #[test]
    fn section_index_of_identifies_the_containing_section() {
        let image = parse(&synthetic_pe32()).unwrap();
        assert_eq!(image.section_index_of(0x401000), Some(0));
        assert_eq!(image.section_index_of(0x402000), Some(1));
        assert_eq!(image.section_index_of(0x2000), None); // below image base
        assert_eq!(image.section_index_of(0x401FFF), None); // between sections
    }

    #[test]
    fn looks_up_sections_case_insensitively() {
        let image = parse(&synthetic_pe32()).unwrap();
        assert_eq!(
            image.section(".RData").map(|s| s.name.as_str()),
            Some(".rdata")
        );
        assert_eq!(image.section(".TEXT").map(|s| s.rva), Some(0x1000));
        assert!(image.section(".nope").is_none());
    }

    #[test]
    fn reports_section_ranges_in_image_base_vas() {
        let image = parse(&synthetic_pe32()).unwrap();
        assert_eq!(image.section_range(".text"), Some((0x401000, 0x401200)));
        assert_eq!(image.section_range(".rdata"), Some((0x402000, 0x402100)));
        assert_eq!(image.section_range(".nope"), None);
    }

    #[test]
    fn prefers_text_for_the_executable_range() {
        let image = parse(&synthetic_pe32()).unwrap();
        assert_eq!(image.executable_range(), Some((0x401000, 0x401200)));
    }

    #[test]
    fn falls_back_to_the_first_execute_section() {
        let mut bytes = synthetic_pe32();
        // Clear EXECUTE on .text.
        let table = 0x84 + 20 + 0xE0;
        bytes[table + 36..table + 40]
            .copy_from_slice(&(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ).to_le_bytes());
        // Give .rdata the execute bit.
        bytes[table + 76..table + 80].copy_from_slice(
            &(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)
                .to_le_bytes(),
        );
        let image = parse(&bytes).unwrap();
        assert_eq!(image.executable_range(), Some((0x401000, 0x401200)));
    }

    #[test]
    fn recognizes_pe32_plus() {
        let mut bytes = synthetic_pe32();
        let opt = 0x84 + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // Magic: PE32+
        bytes[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase (8 bytes)
        let image = parse(&bytes).unwrap();
        assert!(!image.is_pe32);
        assert_eq!(image.image_base, 0x140000000);
        // Addresses stay in the image-base VA space.
        assert_eq!(image.va_to_file(0x140001000), Some(0x200));
        assert_eq!(image.va_to_file(0x401000), None); // below the image base
    }

    #[test]
    fn rejects_truncated_images() {
        let bytes = synthetic_pe32();
        assert!(parse(&bytes[..0x60]).is_err());
        // Cut into the .rdata section table entry (ends at 0x1C8).
        assert!(parse(&bytes[..0x1B0]).is_err());
    }

    #[test]
    fn rejects_bad_magic_and_signature() {
        let mut bytes = synthetic_pe32();
        bytes[0x80..0x84].copy_from_slice(b"XX\0\0");
        assert!(parse(&bytes).is_err());

        let mut bytes = synthetic_pe32();
        let opt = 0x84 + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x10Cu16.to_le_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn not_a_pe_at_all() {
        assert!(parse(b"just some bytes").is_err());
        assert!(parse(&[]).is_err());
    }
}

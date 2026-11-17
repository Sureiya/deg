//! Content-addressed artifacts and address mapping.
//!
//! Nothing in DeG is addressed by a mutable path alone: every `build`,
//! `capture`, `dump`, and `dataset` carries a SHA-256 digest, and evidence is
//! only evaluated against a verified artifact. An unverified artifact can be
//! loaded for diagnostics, but no proof may use it.

use crate::ast::{BuildDecl, CaptureDecl, DatasetDecl, DumpDecl, Item, Model};
use crate::pe::PeImage;
use crate::sha256::sha256_hex;
use crate::value::{find_pattern, parse_byte_pattern, PatternByte};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub enum ArtifactDecl {
    Build(BuildDecl),
    Capture(CaptureDecl),
    Dump(DumpDecl),
    Dataset(DatasetDecl),
}

impl ArtifactDecl {
    pub fn name(&self) -> &str {
        match self {
            ArtifactDecl::Build(d) => &d.name,
            ArtifactDecl::Capture(d) => &d.name,
            ArtifactDecl::Dump(d) => &d.name,
            ArtifactDecl::Dataset(d) => &d.name,
        }
    }

    pub fn declared_sha(&self) -> &str {
        match self {
            ArtifactDecl::Build(d) => &d.sha256,
            ArtifactDecl::Capture(d) => &d.sha256,
            ArtifactDecl::Dump(d) => &d.sha256,
            ArtifactDecl::Dataset(d) => &d.sha256,
        }
    }

    pub fn path(&self) -> &str {
        match self {
            ArtifactDecl::Build(d) => &d.path,
            ArtifactDecl::Capture(d) => &d.path,
            ArtifactDecl::Dump(d) => &d.path,
            ArtifactDecl::Dataset(d) => &d.path,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ArtifactDecl::Build(_) => "binary",
            ArtifactDecl::Capture(_) => "capture",
            ArtifactDecl::Dump(_) => "dump",
            ArtifactDecl::Dataset(_) => "dataset",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedArtifact {
    pub decl: ArtifactDecl,
    pub resolved_path: PathBuf,
    pub bytes: Vec<u8>,
    pub actual_sha256: String,
    pub verified: bool,
    pub load_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArtifactSet {
    pub model_dir: PathBuf,
    pub items: BTreeMap<String, LoadedArtifact>,
    pub errors: Vec<String>,
    /// Parsed PE images, memoized per PE build on first use. Parse errors are
    /// cached too, so a broken PE fails identically everywhere.
    pe_cache: RefCell<BTreeMap<String, Result<PeImage, String>>>,
}

impl ArtifactSet {
    pub fn load(model: &Model, artifacts_root: Option<&Path>) -> ArtifactSet {
        let model_dir = lexical_normalize(
            &Path::new(&model.path)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        );
        let mut items = BTreeMap::new();
        let mut errors = Vec::new();

        for item in &model.items {
            let decl = match item {
                Item::Build(d) => ArtifactDecl::Build(d.clone()),
                Item::Capture(d) => ArtifactDecl::Capture(d.clone()),
                Item::Dump(d) => ArtifactDecl::Dump(d.clone()),
                Item::Dataset(d) => ArtifactDecl::Dataset(d.clone()),
                _ => continue,
            };
            let name = decl.name().to_string();
            if items.contains_key(&name) {
                errors.push(format!("duplicate artifact name `{name}`"));
                continue;
            }
            let declared = decl.declared_sha().to_ascii_lowercase();
            let declared_path = Path::new(decl.path());
            let resolved_path = if declared_path.is_absolute() {
                Some(lexical_normalize(declared_path))
            } else if let Some(root) = artifacts_root {
                let candidate = lexical_normalize(&root.join(declared_path));
                if candidate.exists() {
                    Some(candidate)
                } else {
                    Some(lexical_normalize(&model_dir.join(declared_path)))
                }
            } else {
                Some(lexical_normalize(&model_dir.join(declared_path)))
            };

            let Some(path) = resolved_path else {
                continue;
            };
            match fs::read(&path) {
                Ok(bytes) => {
                    let actual = sha256_hex(&bytes);
                    let verified = actual == declared;
                    if !verified {
                        errors.push(format!(
                            "artifact `{name}` digest mismatch: declared {declared}, actual {actual} ({})",
                            path.display()
                        ));
                    }
                    items.insert(
                        name,
                        LoadedArtifact {
                            decl,
                            resolved_path: path,
                            bytes,
                            actual_sha256: actual,
                            verified,
                            load_error: None,
                        },
                    );
                }
                Err(e) => {
                    let msg = format!("artifact `{name}`: cannot read {}: {e}", path.display());
                    errors.push(msg.clone());
                    items.insert(
                        name,
                        LoadedArtifact {
                            decl,
                            resolved_path: path,
                            bytes: Vec::new(),
                            actual_sha256: String::new(),
                            verified: false,
                            load_error: Some(msg),
                        },
                    );
                }
            }
        }

        ArtifactSet {
            model_dir,
            items,
            errors,
            pe_cache: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn get(&self, name: &str) -> Option<&LoadedArtifact> {
        self.items.get(name)
    }

    pub fn build(&self, name: &str) -> Option<&BuildDecl> {
        match &self.items.get(name)?.decl {
            ArtifactDecl::Build(b) => Some(b),
            _ => None,
        }
    }

    pub fn is_verified(&self, name: &str) -> bool {
        self.items.get(name).map(|a| a.verified).unwrap_or(false)
    }

    pub fn bytes(&self, name: &str) -> Option<&[u8]> {
        self.items
            .get(name)
            .filter(|a| a.verified)
            .map(|a| a.bytes.as_slice())
    }

    pub fn dataset_text(&self, name: &str) -> Result<String, String> {
        let art = self
            .items
            .get(name)
            .ok_or_else(|| format!("unknown dataset `{name}`"))?;
        if !art.verified {
            return Err(format!("dataset `{name}` is not verified"));
        }
        String::from_utf8(art.bytes.clone())
            .map_err(|_| format!("dataset `{name}` is not valid UTF-8"))
    }

    pub fn capture_bytes(&self, name: &str) -> Result<&[u8], String> {
        let art = self
            .items
            .get(name)
            .ok_or_else(|| format!("unknown capture `{name}`"))?;
        if !art.verified {
            return Err(format!("capture `{name}` is not verified"));
        }
        if art.bytes.is_empty() {
            return Err(format!("capture `{name}` is empty or unreadable"));
        }
        Ok(&art.bytes)
    }

    /// Map a virtual address in a build/dump to a file offset. PE builds map
    /// through their section table; raw builds/dumps use the declared load
    /// base / dump base.
    pub fn file_offset(&self, artifact: &str, addr: u64) -> Option<usize> {
        let art = self.items.get(artifact)?;
        if !art.verified {
            return None;
        }
        match &art.decl {
            ArtifactDecl::Build(b) if b.format == "pe" => self.pe(artifact).ok()?.va_to_file(addr),
            ArtifactDecl::Build(b) => {
                let off = addr.checked_sub(b.load)? as usize;
                if off <= art.bytes.len() {
                    Some(off)
                } else {
                    None
                }
            }
            ArtifactDecl::Dump(d) => {
                let off = addr.checked_sub(d.base)? as usize;
                if off <= art.bytes.len() {
                    Some(off)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// The parsed PE image of a `format: pe` build, memoized.
    pub fn pe(&self, build: &str) -> Result<PeImage, String> {
        if let Some(cached) = self.pe_cache.borrow().get(build) {
            return cached.clone();
        }
        let art = self
            .items
            .get(build)
            .ok_or_else(|| format!("unknown build `{build}`"))?;
        let b = match &art.decl {
            ArtifactDecl::Build(b) => b,
            _ => return Err(format!("`{build}` is not a binary build")),
        };
        if b.format != "pe" {
            return Err(format!(
                "build `{build}` is not a PE image (format: {})",
                b.format
            ));
        }
        let parsed = crate::pe::parse(&art.bytes).map_err(|e| format!("build `{build}`: {e}"));
        self.pe_cache
            .borrow_mut()
            .insert(build.to_string(), parsed.clone());
        parsed
    }

    pub fn read_addr(&self, artifact: &str, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        let art = self
            .items
            .get(artifact)
            .ok_or_else(|| format!("unknown artifact `{artifact}`"))?;
        if !art.verified {
            return Err(format!("artifact `{artifact}` is not verified"));
        }
        match &art.decl {
            ArtifactDecl::Build(_) | ArtifactDecl::Dump(_) => {}
            _ => {
                return Err(format!(
                    "artifact `{artifact}` is a {}, not an addressable image",
                    art.decl.kind()
                ))
            }
        }
        // For PE builds, surface a PE parse error instead of a misleading
        // "address outside" message.
        if let ArtifactDecl::Build(b) = &art.decl {
            if b.format == "pe" {
                self.pe(artifact)?;
            }
        }
        let off = self
            .file_offset(artifact, addr)
            .ok_or_else(|| format!("address {addr:#x} is outside `{artifact}`"))?;
        if off + len > art.bytes.len() {
            return Err(format!(
                "read of {len} bytes at {addr:#x} runs past the end of `{artifact}`"
            ));
        }
        Ok(art.bytes[off..off + len].to_vec())
    }

    /// The virtual range of a build's `.text`: a declared `text:` override
    /// wins; a PE build falls back to its executable section; otherwise the
    /// whole image.
    pub fn text_range(&self, build: &str) -> Result<(u64, u64), String> {
        let art = self
            .items
            .get(build)
            .ok_or_else(|| format!("unknown build `{build}`"))?;
        if !art.verified {
            return Err(format!("build `{build}` is not verified"));
        }
        let b = match &art.decl {
            ArtifactDecl::Build(b) => b,
            _ => return Err(format!("`{build}` is not a binary build")),
        };
        match b.text {
            Some((start, end)) => Ok((start, end)),
            None => {
                if b.format == "pe" {
                    self.pe(build)?
                        .executable_range()
                        .ok_or_else(|| format!("PE build `{build}` has no executable section"))
                } else {
                    Ok((b.load, b.load + art.bytes.len() as u64))
                }
            }
        }
    }

    /// The virtual range of a named section. PE builds resolve the name
    /// (case-insensitively) against the parsed section table — even when a
    /// `text:` override exists, section lookup is by name. All ranges are
    /// image-base virtual addresses. Raw builds support only `.text`, which
    /// maps to the declared `text:` range (or the whole image).
    pub fn section_range(&self, build: &str, section: &str) -> Result<(u64, u64), String> {
        let art = self
            .items
            .get(build)
            .ok_or_else(|| format!("unknown build `{build}`"))?;
        if !art.verified {
            return Err(format!("build `{build}` is not verified"));
        }
        let b = match &art.decl {
            ArtifactDecl::Build(b) => b,
            _ => return Err(format!("`{build}` is not a binary build")),
        };
        if b.format == "pe" {
            let image = self.pe(build)?;
            image
                .section_range(section)
                .ok_or_else(|| format!("unknown section {section:?} in PE build `{build}`"))
        } else {
            if section != ".text" {
                return Err(format!(
                    "unknown section {section:?} in raw build `{build}`; only `.text` is supported"
                ));
            }
            self.text_range(build)
        }
    }

    /// The bytes of a named section as `(start VA, slice)`. For PE builds the
    /// virtual range is mapped back to the file through the section table; for
    /// raw builds `.text` is the declared text range.
    pub fn section_bytes<'a>(
        &'a self,
        build: &str,
        section: &str,
    ) -> Result<(u64, &'a [u8]), String> {
        let (start, end) = self.section_range(build, section)?;
        self.range_bytes(build, start, end)
    }

    /// The bytes of a build's `.text` as `(start VA, slice)`. Kept for
    /// compatibility; equivalent to `section_bytes(build, ".text")` for raw
    /// builds and to the declared/derived text range for PE builds.
    pub fn text_bytes<'a>(&'a self, build: &str) -> Result<(u64, &'a [u8]), String> {
        let (start, end) = self.text_range(build)?;
        self.range_bytes(build, start, end)
    }

    /// Slice a virtual range `start..end` of a build out of the file. Raw
    /// builds subtract the load base; PE builds map both endpoints through
    /// the section table and reject ranges that span more than one section.
    fn range_bytes<'a>(
        &'a self,
        build: &str,
        start: u64,
        end: u64,
    ) -> Result<(u64, &'a [u8]), String> {
        if start >= end {
            return Err(format!(
                "empty address range {start:#x}..{end:#x} in `{build}`"
            ));
        }
        let art = self
            .items
            .get(build)
            .ok_or_else(|| format!("unknown build `{build}`"))?;
        let b = match &art.decl {
            ArtifactDecl::Build(b) => b,
            _ => return Err(format!("`{build}` is not a binary build")),
        };
        let (start_off, end_off) = if b.format == "pe" {
            let image = self.pe(build)?;
            let start_off = image.va_to_file(start).ok_or_else(|| {
                format!("address {start:#x} is outside every section of `{build}`")
            })?;
            let end_off = image
                .va_to_file(end - 1)
                .map(|off| off + 1)
                .ok_or_else(|| format!("address {end:#x} is outside every section of `{build}`"))?;
            // A range whose endpoints land in different sections must not be
            // sliced across the inter-section file padding. Only a declared
            // `text:` override can produce such a range; a section's own
            // range never does.
            if image.section_index_of(start) != image.section_index_of(end - 1) {
                return Err(format!(
                    "range {start:#x}..{end:#x} spans multiple sections of `{build}`"
                ));
            }
            (start_off, end_off)
        } else {
            let start_off = start.checked_sub(b.load).ok_or_else(|| {
                format!("range start {start:#x} is below image base {:#x}", b.load)
            })? as usize;
            let end_off = end
                .checked_sub(b.load)
                .ok_or_else(|| format!("range end {end:#x} is below image base {:#x}", b.load))?
                as usize;
            (start_off, end_off)
        };
        if start_off > art.bytes.len() || end_off > art.bytes.len() || start_off >= end_off {
            return Err(format!(
                "range {start:#x}..{end:#x} is outside `{build}` ({} bytes)",
                art.bytes.len()
            ));
        }
        Ok((start, &art.bytes[start_off..end_off]))
    }

    /// Scan a named section of a build for a byte pattern. Returned addresses
    /// are virtual (raw builds: load base + offset).
    pub fn scan_build(
        &self,
        build: &str,
        section: &str,
        pattern: &str,
    ) -> Result<Vec<u64>, String> {
        let parsed = parse_byte_pattern(pattern)?;
        self.scan_build_pattern(build, section, &parsed)
    }

    /// Scan a build's `.text`; kept as a compatibility wrapper.
    pub fn scan_build_text(&self, build: &str, pattern: &str) -> Result<Vec<u64>, String> {
        self.scan_build(build, ".text", pattern)
    }

    /// Scan a named section of a build for a pre-parsed byte pattern.
    pub fn scan_build_pattern(
        &self,
        build: &str,
        section: &str,
        pattern: &[PatternByte],
    ) -> Result<Vec<u64>, String> {
        let (start, bytes) = self.section_bytes(build, section)?;
        let hits = find_pattern(bytes, pattern);
        Ok(hits.into_iter().map(|off| start + off as u64).collect())
    }
}

/// Collapse `.` and `..` components without touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let popped = out.pop();
                if !popped {
                    out.push("..");
                }
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                out.push(component.as_os_str())
            }
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

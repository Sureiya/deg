//! Content-addressed artifacts and address mapping.
//!
//! Nothing in DeG is addressed by a mutable path alone: every `build`,
//! `capture`, `dump`, and `dataset` carries a SHA-256 digest, and evidence is
//! only evaluated against a verified artifact. An unverified artifact can be
//! loaded for diagnostics, but no proof may use it.

use crate::ast::{BuildDecl, CaptureDecl, DatasetDecl, DumpDecl, Item, Model};
use crate::sha256::sha256_hex;
use crate::value::{find_pattern, parse_byte_pattern, PatternByte};
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

    /// Map a virtual address in a build/dump to a file offset.
    pub fn file_offset(&self, artifact: &str, addr: u64) -> Option<usize> {
        let art = self.items.get(artifact)?;
        if !art.verified {
            return None;
        }
        let base = match &art.decl {
            ArtifactDecl::Build(b) => b.load,
            ArtifactDecl::Dump(d) => d.base,
            _ => return None,
        };
        let off = addr.checked_sub(base)? as usize;
        if off <= art.bytes.len() {
            Some(off)
        } else {
            None
        }
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

    /// The virtual range of a build's `.text`, or the whole image if no range
    /// was declared.
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
            None => Ok((b.load, b.load + art.bytes.len() as u64)),
        }
    }

    pub fn text_bytes<'a>(&'a self, build: &str) -> Result<(u64, &'a [u8]), String> {
        let (start, end) = self.text_range(build)?;
        let art = self
            .items
            .get(build)
            .ok_or_else(|| format!("unknown build `{build}`"))?;
        let b = match &art.decl {
            ArtifactDecl::Build(b) => b,
            _ => return Err(format!("`{build}` is not a binary build")),
        };
        let start_off = start
            .checked_sub(b.load)
            .ok_or_else(|| format!("text start {start:#x} is below image base {:#x}", b.load))?
            as usize;
        let end_off = end
            .checked_sub(b.load)
            .ok_or_else(|| format!("text end {end:#x} is below image base {:#x}", b.load))?
            as usize;
        if start_off > art.bytes.len() || end_off > art.bytes.len() || start_off >= end_off {
            return Err(format!(
                "text range {start:#x}..{end:#x} is outside `{build}` ({} bytes)",
                art.bytes.len()
            ));
        }
        Ok((start, &art.bytes[start_off..end_off]))
    }

    pub fn scan_build(&self, build: &str, pattern: &str) -> Result<Vec<u64>, String> {
        let parsed = parse_byte_pattern(pattern)?;
        let (start, bytes) = self.text_bytes(build)?;
        let hits = find_pattern(bytes, &parsed);
        Ok(hits.into_iter().map(|off| start + off as u64).collect())
    }

    pub fn scan_build_pattern(
        &self,
        build: &str,
        pattern: &[PatternByte],
    ) -> Result<Vec<u64>, String> {
        let (start, bytes) = self.text_bytes(build)?;
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

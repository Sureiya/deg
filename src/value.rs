//! Ground values used by the fact store, rules, and certificates.
//!
//! Values are totally ordered and hashable so they can be keys in the fact
//! store. Floating-point numbers do not appear here: measurements are stored as
//! integer microseconds/millis, and statistics are computed in `stats`.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    Int(i128),
    Bool(bool),
    /// A symbol or a model reference, e.g. `MT19937` or `S2C_Position.pos`.
    Sym(String),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    /// Microseconds.
    Duration(u64),
}

impl Value {
    pub fn int(n: i128) -> Value {
        Value::Int(n)
    }

    pub fn sym(s: impl Into<String>) -> Value {
        Value::Sym(s.into())
    }

    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    pub fn list(items: Vec<Value>) -> Value {
        Value::List(items)
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(n) => Some(*n),
            Value::Duration(n) => Some(*n as i128),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_int().and_then(|n| u64::try_from(n).ok())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Sym(s) | Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(v) => Some(v),
            _ => None,
        }
    }

    /// A display form that is stable enough for reports and JSON output.
    pub fn display(&self) -> String {
        match self {
            Value::Int(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Sym(s) => s.clone(),
            Value::Str(s) => format!("{s:?}"),
            Value::Bytes(b) => {
                let mut out = String::from("0x");
                for byte in b {
                    out.push_str(&format!("{byte:02x}"));
                }
                out
            }
            Value::List(items) => {
                let inner: Vec<String> = items.iter().map(|v| v.display()).collect();
                format!("[{}]", inner.join(", "))
            }
            Value::Duration(us) => format_duration(*us),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

pub fn format_duration(us: u64) -> String {
    if us == 0 {
        "0us".to_string()
    } else if us % 86_400_000_000 == 0 {
        format!("{}d", us / 86_400_000_000)
    } else if us % 3_600_000_000 == 0 {
        format!("{}h", us / 3_600_000_000)
    } else if us % 60_000_000 == 0 {
        format!("{}m", us / 60_000_000)
    } else if us % 1_000_000 == 0 {
        format!("{}s", us / 1_000_000)
    } else if us % 1_000 == 0 {
        format!("{}ms", us / 1_000)
    } else {
        format!("{us}us")
    }
}

/// A literal as written in a model or rule.
#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Int(i128),
    Bool(bool),
    Sym(String),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Lit>),
    Duration(u64),
    Float(f64),
}

impl Lit {
    /// Convert a literal to a ground value, rejecting floats (which are only
    /// meaningful in statistical claims, not in the fact store).
    pub fn to_value(&self) -> Result<Value, String> {
        match self {
            Lit::Int(n) => Ok(Value::Int(*n)),
            Lit::Bool(b) => Ok(Value::Bool(*b)),
            Lit::Sym(s) => Ok(Value::Sym(s.clone())),
            Lit::Str(s) => Ok(Value::Sym(s.clone())),
            Lit::Bytes(b) => Ok(Value::Bytes(b.clone())),
            Lit::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.to_value()?);
                }
                Ok(Value::List(out))
            }
            Lit::Duration(us) => Ok(Value::Duration(*us)),
            Lit::Float(f) => Err(format!(
                "floating-point literal {f} is not allowed in a fact or rule"
            )),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Lit::Int(n) => n.to_string(),
            Lit::Bool(b) => b.to_string(),
            Lit::Sym(s) => s.clone(),
            Lit::Str(s) => format!("{s:?}"),
            Lit::Bytes(b) => {
                let mut out = String::from("0x");
                for byte in b {
                    out.push_str(&format!("{byte:02x}"));
                }
                out
            }
            Lit::List(items) => {
                let inner: Vec<String> = items.iter().map(Lit::display).collect();
                format!("[{}]", inner.join(", "))
            }
            Lit::Duration(us) => format_duration(*us),
            Lit::Float(f) => format!("{f}"),
        }
    }
}

pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ',' && *c != '_')
        .collect();
    if compact.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {s:?}"));
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    let bytes = compact.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", b as char)),
    }
}

/// Parse a byte pattern such as `"F3 0F 10 47 ?? 48 8D 4F ??"`.
/// Each element is a byte or a full-byte wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternByte {
    Byte(u8),
    Any,
}

pub fn parse_byte_pattern(s: &str) -> Result<Vec<PatternByte>, String> {
    let mut out = Vec::new();
    for tok in s.split_whitespace() {
        if tok == "??" || tok == "?" || tok == "**" {
            out.push(PatternByte::Any);
        } else if tok.len() == 2 {
            let b =
                u8::from_str_radix(tok, 16).map_err(|_| format!("invalid pattern byte {tok:?}"))?;
            out.push(PatternByte::Byte(b));
        } else if tok.len() > 2 && tok.len() % 2 == 0 {
            // Accept compact patterns such as "F30F1047??".
            let chars: Vec<char> = tok.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let pair: String = chars[i..i + 2].iter().collect();
                if pair == "??" {
                    out.push(PatternByte::Any);
                } else {
                    let b = u8::from_str_radix(&pair, 16)
                        .map_err(|_| format!("invalid pattern byte {pair:?}"))?;
                    out.push(PatternByte::Byte(b));
                }
                i += 2;
            }
        } else {
            return Err(format!("invalid pattern token {tok:?}"));
        }
    }
    if out.is_empty() {
        return Err("empty byte pattern".to_string());
    }
    Ok(out)
}

/// Search a haystack for every (possibly overlapping) match of a pattern.
pub fn find_pattern(haystack: &[u8], pattern: &[PatternByte]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for start in 0..=haystack.len() - pattern.len() {
        let mut ok = true;
        for (i, p) in pattern.iter().enumerate() {
            match p {
                PatternByte::Any => {}
                PatternByte::Byte(b) => {
                    if haystack[start + i] != *b {
                        ok = false;
                        break;
                    }
                }
            }
        }
        if ok {
            hits.push(start);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_bytes_ignore_separators() {
        assert_eq!(
            parse_hex_bytes("f3 0f,10_47").unwrap(),
            vec![0xf3, 0x0f, 0x10, 0x47]
        );
        assert!(parse_hex_bytes("abc").is_err());
    }

    #[test]
    fn patterns_match_with_wildcards() {
        let pat = parse_byte_pattern("F3 0F 10 47 ??").unwrap();
        let hay = [0xf3, 0x0f, 0x10, 0x47, 0x08, 0xf3, 0x0f];
        assert_eq!(find_pattern(&hay, &pat), vec![0]);
    }

    #[test]
    fn compact_patterns_are_accepted() {
        let pat = parse_byte_pattern("F30F1047??").unwrap();
        assert_eq!(pat.len(), 5);
    }

    #[test]
    fn durations_display_compactly() {
        assert_eq!(format_duration(15_625), "15625us");
        assert_eq!(format_duration(50_000), "50ms");
        assert_eq!(format_duration(100_000_000), "100s");
    }
}

//! A tiny JSON parser/writer for certificates, symbol stores, and lock files.
//! No external dependencies: the checker must build from source alone.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> BTreeMap<String, Json> {
        BTreeMap::new()
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if *n >= 0.0 => Some(*n as u64),
            Json::Str(s) => {
                let s = s.trim();
                if let Some(rest) = s.strip_prefix("0x") {
                    u64::from_str_radix(rest, 16).ok()
                } else {
                    s.parse().ok()
                }
            }
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Obj(v) => Some(v),
            _ => None,
        }
    }

    pub fn string_array(&self) -> Option<Vec<String>> {
        self.as_arr().map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_json(self, f, 0)
    }
}

fn write_json(v: &Json, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
    match v {
        Json::Null => f.write_str("null"),
        Json::Bool(b) => write!(f, "{b}"),
        Json::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                write!(f, "{}", *n as i64)
            } else {
                write!(f, "{n}")
            }
        }
        Json::Str(s) => write_escaped(f, s),
        Json::Arr(items) => {
            if items.is_empty() {
                return f.write_str("[]");
            }
            f.write_str("[\n")?;
            for (i, item) in items.iter().enumerate() {
                write_indent(f, indent + 2)?;
                write_json(item, f, indent + 2)?;
                if i + 1 < items.len() {
                    f.write_str(",")?;
                }
                f.write_str("\n")?;
            }
            write_indent(f, indent)?;
            f.write_str("]")
        }
        Json::Obj(map) => {
            if map.is_empty() {
                return f.write_str("{}");
            }
            f.write_str("{\n")?;
            for (i, (key, val)) in map.iter().enumerate() {
                write_indent(f, indent + 2)?;
                write_escaped(f, key)?;
                f.write_str(": ")?;
                write_json(val, f, indent + 2)?;
                if i + 1 < map.len() {
                    f.write_str(",")?;
                }
                f.write_str("\n")?;
            }
            write_indent(f, indent)?;
            f.write_str("}")
        }
    }
}

fn write_indent(f: &mut fmt::Formatter<'_>, n: usize) -> fmt::Result {
    for _ in 0..n {
        f.write_str(" ")?;
    }
    Ok(())
}

pub fn write_escaped(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_str("\"")?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing JSON at byte {}", p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected {:?} at byte {}, found {:?}",
                b as char,
                self.pos,
                self.peek().map(char::from)
            ))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            None => Err("unexpected end of JSON".into()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => {
                self.expect_word("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.expect_word("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.expect_word("null")?;
                Ok(Json::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(other) => Err(format!("unexpected JSON byte {:?}", other as char)),
        }
    }

    fn expect_word(&mut self, word: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(format!("expected {word:?} at byte {}", self.pos))
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            let val = self.value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                other => {
                    return Err(format!(
                        "expected ',' or '}}' in object at byte {}, found {:?}",
                        self.pos - 1,
                        other.map(char::from)
                    ))
                }
            }
        }
        Ok(Json::Obj(map))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                other => {
                    return Err(format!(
                        "expected ',' or ']' in array at byte {}, found {:?}",
                        self.pos - 1,
                        other.map(char::from)
                    ))
                }
            }
        }
        Ok(Json::Arr(items))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.bump().ok_or("unterminated string")?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump().ok_or("unterminated escape")?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let h = self.bump().ok_or("truncated \\u escape")?;
                                code = code * 16 + hex_digit(h)? as u32;
                            }
                            let c = char::from_u32(code)
                                .ok_or_else(|| format!("invalid unicode escape {code:04x}"))?;
                            out.push(c);
                        }
                        other => return Err(format!("invalid escape \\{}", other as char)),
                    }
                }
                b if b < 0x20 => return Err("control character in JSON string".into()),
                _ => {
                    // Decode a UTF-8 sequence starting with this byte.
                    let start = self.pos - 1;
                    let width = utf8_width(b);
                    let end = (start + width).min(self.bytes.len());
                    let s = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                    out.push_str(s);
                    self.pos = end;
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number {s:?}"))
    }
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", b as char)),
    }
}

fn utf8_width(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_certificates() {
        let j = parse(r#"{"kind":"trace","n":3,"ok":true,"xs":[1,2,"x"]}"#).unwrap();
        assert_eq!(j.get("kind").unwrap().as_str(), Some("trace"));
        assert_eq!(j.get("n").unwrap().as_u64(), Some(3));
        assert_eq!(j.get("ok").unwrap().as_bool(), Some(true));
        assert_eq!(j.get("xs").unwrap().as_arr().unwrap().len(), 3);
    }

    #[test]
    fn roundtrips_escapes() {
        let j = Json::Str("a\"b\nc".into());
        let text = j.to_string();
        let back = parse(&text).unwrap();
        assert_eq!(j, back);
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse("{} x").is_err());
    }
}

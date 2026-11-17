//! Lexer for DeG model files.
//!
//! The surface language is ASCII-first, but the symbols used in the design
//! notes (`±`, `≈`, `∧`, `⇒`, `⊨`, `≤`, `≥`) are accepted as aliases so that
//! documentation and checked sources can look the same.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub col: u32,
    pub offset: usize,
}

impl Span {
    pub fn new(line: u32, col: u32, offset: usize) -> Span {
        Span { line, col, offset }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    Int(i128),
    Float(f64),
    Str(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Colon,
    ColonEq,
    Eq,
    EqEq,
    At,
    Dot,
    DotDot,
    Pipe,
    PipeGt,
    Tilde,
    PlusMinus,
    Le,
    Ge,
    Lt,
    Gt,
    Plus,
    Minus,
    Star,
    Slash,
    Bang,
    Question,
    And,
    Or,
    Arrow,
    FatArrow,
    Turnstile,
    Eof,
}

impl Token {
    pub fn describe(&self) -> String {
        match self {
            Token::Ident(s) => format!("identifier `{s}`"),
            Token::Int(n) => format!("integer {n}"),
            Token::Float(v) => format!("number {v}"),
            Token::Str(_) => "string".to_string(),
            Token::LBrace => "`{`".into(),
            Token::RBrace => "`}`".into(),
            Token::LParen => "`(`".into(),
            Token::RParen => "`)`".into(),
            Token::LBracket => "`[`".into(),
            Token::RBracket => "`]`".into(),
            Token::Comma => "`,`".into(),
            Token::Semi => "`;`".into(),
            Token::Colon => "`:`".into(),
            Token::ColonEq => "`:=`".into(),
            Token::Eq => "`=`".into(),
            Token::EqEq => "`==`".into(),
            Token::At => "`@`".into(),
            Token::Dot => "`.`".into(),
            Token::DotDot => "`..`".into(),
            Token::Pipe => "`|`".into(),
            Token::PipeGt => "`|>`".into(),
            Token::Tilde => "`~`".into(),
            Token::PlusMinus => "`+-`".into(),
            Token::Le => "`<=`".into(),
            Token::Ge => "`>=`".into(),
            Token::Lt => "`<`".into(),
            Token::Gt => "`>`".into(),
            Token::Plus => "`+`".into(),
            Token::Minus => "`-`".into(),
            Token::Star => "`*`".into(),
            Token::Slash => "`/`".into(),
            Token::Bang => "`!`".into(),
            Token::Question => "`?`".into(),
            Token::And => "`and`".into(),
            Token::Or => "`or`".into(),
            Token::Arrow => "`->`".into(),
            Token::FatArrow => "`=>`".into(),
            Token::Turnstile => "`|=`".into(),
            Token::Eof => "end of file".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenWithSpan {
    pub token: Token,
    pub span: Span,
}

pub fn lex(input: &str) -> Result<Vec<TokenWithSpan>, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1u32;
    let mut col = 1u32;

    let advance = |i: &mut usize, line: &mut u32, col: &mut u32, c: char| {
        *i += c.len_utf8();
        if c == '\n' {
            *line += 1;
            *col = 1;
        } else {
            *col += 1;
        }
    };

    while i < bytes.len() {
        let start = Span::new(line, col, i);
        let c = input[i..].chars().next().unwrap();
        match c {
            ' ' | '\t' | '\r' => {
                advance(&mut i, &mut line, &mut col, c);
                continue;
            }
            '\n' => {
                advance(&mut i, &mut line, &mut col, c);
                continue;
            }
            '/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap();
                    if ch == '\n' {
                        break;
                    }
                    advance(&mut i, &mut line, &mut col, ch);
                }
                continue;
            }
            '/' if bytes.get(i + 1) == Some(&b'*') => {
                advance(&mut i, &mut line, &mut col, '/');
                advance(&mut i, &mut line, &mut col, '*');
                let mut closed = false;
                while i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap();
                    if ch == '*' && bytes.get(i + 1) == Some(&b'/') {
                        advance(&mut i, &mut line, &mut col, '*');
                        advance(&mut i, &mut line, &mut col, '/');
                        closed = true;
                        break;
                    }
                    advance(&mut i, &mut line, &mut col, ch);
                }
                if !closed {
                    return Err(format!("{start}: unterminated block comment"));
                }
                continue;
            }
            _ => {}
        }

        macro_rules! emit {
            ($tok:expr) => {{
                out.push(TokenWithSpan {
                    token: $tok,
                    span: start,
                });
                advance(&mut i, &mut line, &mut col, c);
            }};
        }

        // Multi-character ASCII operators first.
        let rest = &input[i..];
        if rest.starts_with("|>") {
            out.push(TokenWithSpan {
                token: Token::PipeGt,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '|');
            advance(&mut i, &mut line, &mut col, '>');
            continue;
        }
        if rest.starts_with(":=") {
            out.push(TokenWithSpan {
                token: Token::ColonEq,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, ':');
            advance(&mut i, &mut line, &mut col, '=');
            continue;
        }
        if rest.starts_with("==") {
            out.push(TokenWithSpan {
                token: Token::EqEq,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '=');
            advance(&mut i, &mut line, &mut col, '=');
            continue;
        }
        if rest.starts_with("..") {
            out.push(TokenWithSpan {
                token: Token::DotDot,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '.');
            advance(&mut i, &mut line, &mut col, '.');
            continue;
        }
        if rest.starts_with("<=") {
            out.push(TokenWithSpan {
                token: Token::Le,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '<');
            advance(&mut i, &mut line, &mut col, '=');
            continue;
        }
        if rest.starts_with(">=") {
            out.push(TokenWithSpan {
                token: Token::Ge,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '>');
            advance(&mut i, &mut line, &mut col, '=');
            continue;
        }
        if rest.starts_with("=>") {
            out.push(TokenWithSpan {
                token: Token::FatArrow,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '=');
            advance(&mut i, &mut line, &mut col, '>');
            continue;
        }
        if rest.starts_with("->") {
            out.push(TokenWithSpan {
                token: Token::Arrow,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '-');
            advance(&mut i, &mut line, &mut col, '>');
            continue;
        }
        if rest.starts_with("|=") {
            out.push(TokenWithSpan {
                token: Token::Turnstile,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '|');
            advance(&mut i, &mut line, &mut col, '=');
            continue;
        }
        if rest.starts_with("+-") {
            out.push(TokenWithSpan {
                token: Token::PlusMinus,
                span: start,
            });
            advance(&mut i, &mut line, &mut col, '+');
            advance(&mut i, &mut line, &mut col, '-');
            continue;
        }

        match c {
            '{' => emit!(Token::LBrace),
            '}' => emit!(Token::RBrace),
            '(' => emit!(Token::LParen),
            ')' => emit!(Token::RParen),
            '[' => emit!(Token::LBracket),
            ']' => emit!(Token::RBracket),
            ',' => emit!(Token::Comma),
            ';' => emit!(Token::Semi),
            ':' => emit!(Token::Colon),
            '=' => emit!(Token::Eq),
            '@' => emit!(Token::At),
            '.' => emit!(Token::Dot),
            '|' => emit!(Token::Pipe),
            '<' => emit!(Token::Lt),
            '>' => emit!(Token::Gt),
            '+' => emit!(Token::Plus),
            '*' => emit!(Token::Star),
            '/' => emit!(Token::Slash),
            '!' => emit!(Token::Bang),
            '?' => emit!(Token::Question),
            '~' => emit!(Token::Tilde),
            '±' => emit!(Token::PlusMinus),
            '≈' => emit!(Token::Tilde),
            '∧' => emit!(Token::And),
            '∨' => emit!(Token::Or),
            '⇒' => emit!(Token::FatArrow),
            '⊨' => emit!(Token::Turnstile),
            '→' => emit!(Token::Arrow),
            '≤' => emit!(Token::Le),
            '≥' => emit!(Token::Ge),
            '-' => emit!(Token::Minus),
            '"' => {
                let mut s = String::new();
                advance(&mut i, &mut line, &mut col, '"');
                let mut closed = false;
                while i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap();
                    if ch == '"' {
                        advance(&mut i, &mut line, &mut col, '"');
                        closed = true;
                        break;
                    }
                    if ch == '\n' {
                        return Err(format!("{start}: unterminated string literal"));
                    }
                    if ch == '\\' {
                        advance(&mut i, &mut line, &mut col, '\\');
                        let esc = input[i..]
                            .chars()
                            .next()
                            .ok_or_else(|| format!("{start}: unterminated escape"))?;
                        match esc {
                            'n' => s.push('\n'),
                            'r' => s.push('\r'),
                            't' => s.push('\t'),
                            '\\' => s.push('\\'),
                            '"' => s.push('"'),
                            '0' => s.push('\0'),
                            'x' => {
                                advance(&mut i, &mut line, &mut col, 'x');
                                let h1 = input[i..].chars().next().ok_or("bad \\x")?;
                                advance(&mut i, &mut line, &mut col, h1);
                                let h2 = input[i..].chars().next().ok_or("bad \\x")?;
                                advance(&mut i, &mut line, &mut col, h2);
                                let hex = format!("{h1}{h2}");
                                let b = u8::from_str_radix(&hex, 16)
                                    .map_err(|_| format!("{start}: bad \\x{hex}"))?;
                                s.push(b as char);
                            }
                            other => {
                                return Err(format!("{start}: unsupported escape \\{}", other))
                            }
                        }
                        advance(&mut i, &mut line, &mut col, esc);
                        continue;
                    }
                    s.push(ch);
                    advance(&mut i, &mut line, &mut col, ch);
                }
                if !closed {
                    return Err(format!("{start}: unterminated string literal"));
                }
                out.push(TokenWithSpan {
                    token: Token::Str(s),
                    span: start,
                });
            }
            '0'..='9' => {
                let num_start = i;
                let mut is_float = false;
                if rest.starts_with("0x") || rest.starts_with("0X") {
                    advance(&mut i, &mut line, &mut col, '0');
                    advance(&mut i, &mut line, &mut col, 'x');
                    let ds = i;
                    while i < bytes.len() {
                        let ch = input[i..].chars().next().unwrap();
                        if ch.is_ascii_hexdigit() || ch == '_' {
                            advance(&mut i, &mut line, &mut col, ch);
                        } else {
                            break;
                        }
                    }
                    let text: String = input[ds..i].chars().filter(|c| *c != '_').collect();
                    if text.is_empty() {
                        return Err(format!("{start}: expected hex digits after 0x"));
                    }
                    let n = i128::from_str_radix(&text, 16)
                        .map_err(|_| format!("{start}: integer out of range"))?;
                    out.push(TokenWithSpan {
                        token: Token::Int(n),
                        span: start,
                    });
                    continue;
                }
                if rest.starts_with("0b") || rest.starts_with("0B") {
                    advance(&mut i, &mut line, &mut col, '0');
                    advance(&mut i, &mut line, &mut col, 'b');
                    let ds = i;
                    while i < bytes.len() {
                        let ch = input[i..].chars().next().unwrap();
                        if ch == '0' || ch == '1' || ch == '_' {
                            advance(&mut i, &mut line, &mut col, ch);
                        } else {
                            break;
                        }
                    }
                    let text: String = input[ds..i].chars().filter(|c| *c != '_').collect();
                    let n = i128::from_str_radix(&text, 2)
                        .map_err(|_| format!("{start}: integer out of range"))?;
                    out.push(TokenWithSpan {
                        token: Token::Int(n),
                        span: start,
                    });
                    continue;
                }
                while i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap();
                    if ch.is_ascii_digit() || ch == '_' {
                        advance(&mut i, &mut line, &mut col, ch);
                    } else {
                        break;
                    }
                }
                if i < bytes.len() && input[i..].starts_with('.') && !input[i..].starts_with("..") {
                    is_float = true;
                    advance(&mut i, &mut line, &mut col, '.');
                    while i < bytes.len() {
                        let ch = input[i..].chars().next().unwrap();
                        if ch.is_ascii_digit() {
                            advance(&mut i, &mut line, &mut col, ch);
                        } else {
                            break;
                        }
                    }
                }
                if i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap();
                    if ch == 'e' || ch == 'E' {
                        is_float = true;
                        advance(&mut i, &mut line, &mut col, ch);
                        if i < bytes.len() {
                            let sign = input[i..].chars().next().unwrap();
                            if sign == '+' || sign == '-' {
                                advance(&mut i, &mut line, &mut col, sign);
                            }
                        }
                        while i < bytes.len() {
                            let d = input[i..].chars().next().unwrap();
                            if d.is_ascii_digit() {
                                advance(&mut i, &mut line, &mut col, d);
                            } else {
                                break;
                            }
                        }
                    }
                }
                let text: String = input[num_start..i].chars().filter(|c| *c != '_').collect();
                if is_float {
                    let v = text
                        .parse::<f64>()
                        .map_err(|_| format!("{start}: invalid number {text:?}"))?;
                    out.push(TokenWithSpan {
                        token: Token::Float(v),
                        span: start,
                    });
                } else {
                    let n = text
                        .parse::<i128>()
                        .map_err(|_| format!("{start}: integer out of range"))?;
                    out.push(TokenWithSpan {
                        token: Token::Int(n),
                        span: start,
                    });
                }
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let ds = i;
                while i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap();
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        advance(&mut i, &mut line, &mut col, ch);
                    } else {
                        break;
                    }
                }
                let ident = input[ds..i].to_string();
                let token = match ident.as_str() {
                    "and" => Token::And,
                    "or" => Token::Or,
                    _ => Token::Ident(ident),
                };
                out.push(TokenWithSpan { token, span: start });
            }
            other => {
                return Err(format!("{start}: unexpected character {other:?}"));
            }
        }
    }

    out.push(TokenWithSpan {
        token: Token::Eof,
        span: Span::new(line, col, i),
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Token> {
        lex(s).unwrap().into_iter().map(|t| t.token).collect()
    }

    #[test]
    fn lexes_operators_and_unicode() {
        let t = toks("a := b |> c ~ d ± e <= f ≥ g ∧ h ⇒ i ⊨ j");
        assert!(t.contains(&Token::ColonEq));
        assert!(t.contains(&Token::PipeGt));
        assert!(t.contains(&Token::Tilde));
        assert!(t.contains(&Token::PlusMinus));
        assert!(t.contains(&Token::Le));
        assert!(t.contains(&Token::Ge));
        assert!(t.contains(&Token::And));
        assert!(t.contains(&Token::FatArrow));
        assert!(t.contains(&Token::Turnstile));
    }

    #[test]
    fn lexes_numbers() {
        let t = toks("0x140012345 0b1010 15.625 1e-4");
        assert_eq!(t[0], Token::Int(0x140012345));
        assert_eq!(t[1], Token::Int(10));
        assert_eq!(t[2], Token::Float(15.625));
        assert_eq!(t[3], Token::Float(1e-4));
    }

    #[test]
    fn lexes_strings_and_comments() {
        let t = toks("// hello\n\"F3 0F\" /* block */ \"x\\\"y\"");
        assert_eq!(t[0], Token::Str("F3 0F".into()));
        assert_eq!(t[1], Token::Str("x\"y".into()));
    }

    #[test]
    fn spans_track_lines() {
        let ts = lex("a\n  b").unwrap();
        assert_eq!(ts[0].span.line, 1);
        assert_eq!(ts[1].span.line, 2);
        assert_eq!(ts[1].span.col, 3);
    }
}

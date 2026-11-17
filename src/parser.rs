//! Recursive-descent parser for `.dg` models.
//!
//! The grammar is documented in `docs/grammar.ebnf`; this file is deliberately
//! strict about statement terminators and required artifact digests so that a
//! checked model is also a reproducible one.

use crate::ast::*;
use crate::lexer::{lex, Span, Token, TokenWithSpan};
use crate::strength::Strength;
use crate::value::Lit;

pub fn parse_model(path: &str, input: &str) -> Result<Model, String> {
    let tokens = lex(input)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        path: path.to_string(),
    };
    parser.model()
}

struct Parser<'a> {
    tokens: &'a [TokenWithSpan],
    pos: usize,
    path: String,
}

impl<'a> Parser<'a> {
    fn model(&mut self) -> Result<Model, String> {
        let mut items = Vec::new();
        while !matches!(self.peek(), Token::Eof) {
            items.push(self.item()?);
        }
        Ok(Model {
            path: self.path.clone(),
            items,
        })
    }

    fn item(&mut self) -> Result<Item, String> {
        let span = self.span();
        let word = self.ident()?;
        match word.as_str() {
            "pragma" => self.pragma(span).map(Item::Pragma),
            "build" => self.build(span).map(Item::Build),
            "capture" => self.capture(span).map(Item::Capture),
            "dump" => self.dump(span).map(Item::Dump),
            "dataset" => self.dataset(span).map(Item::Dataset),
            "clock" => self.clock(span).map(Item::Clock),
            "relate" => self.relate(span).map(Item::Relate),
            "struct" => self.struct_decl(span).map(Item::Struct),
            "packet" => self.packet(span).map(Item::Packet),
            "fn" => self.fn_decl(span).map(Item::Fn),
            "rng" => self.rng_decl(span).map(Item::Rng),
            "dist" => self.dist_decl(span).map(Item::Dist),
            "ev" => self.evidence(span).map(Item::Evidence),
            "rule" => self.rule(span).map(Item::Rule),
            "proof" => self.proof(span).map(Item::Proof),
            "claim" => self.claim(span).map(Item::Claim),
            "conflict" => self.conflict(span).map(Item::Conflict),
            "decision" => self.decision(span).map(Item::Decision),
            "obligation" => self.obligation(span).map(Item::Obligation),
            "refute" => self.refute(span).map(Item::Refute),
            "port" => self.port(span).map(Item::Port),
            other => Err(self.err(span, format!("unknown top-level declaration `{other}`"))),
        }
    }

    // ------------------------------------------------------------------
    // Artifacts and pragmas
    // ------------------------------------------------------------------

    fn pragma(&mut self, span: Span) -> Result<PragmaDecl, String> {
        let key = self.ident()?;
        self.expect(Token::Eq)?;
        let value = self.value()?;
        self.expect(Token::Semi)?;
        Ok(PragmaDecl { key, value, span })
    }

    fn build(&mut self, span: Span) -> Result<BuildDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Eq)?;
        let kind = self.ident()?;
        if kind != "binary" {
            return Err(self.err(span, format!("build must be `binary(...)`, found `{kind}`")));
        }
        let args = self.args()?;
        self.expect(Token::Semi)?;
        let path = self.need_pos_string(&args, 0, "build path", span)?;
        let sha256 = self.need_string(&args, "sha256", "build digest", span)?;
        let arch = args.string("arch").unwrap_or_else(|| "unknown".to_string());
        let format = match args.string("format") {
            Some(f) => {
                let f = f.trim().to_ascii_lowercase();
                if !matches!(f.as_str(), "raw" | "pe") {
                    return Err(self.err(
                        span,
                        format!("build format must be `raw` or `pe`, found {f:?}"),
                    ));
                }
                f
            }
            None => "raw".to_string(),
        };
        let load = args.u64("load").unwrap_or(0);
        let text = match args.get("text") {
            Some(ArgVal::Range(a, b)) => Some((*a, *b)),
            Some(other) => {
                return Err(self.err(
                    span,
                    format!(
                        "`text:` expects a range like 0x1000..0x1400, found {}",
                        other.display()
                    ),
                ))
            }
            None => None,
        };
        validate_sha256(&sha256, &self.path, span)?;
        Ok(BuildDecl {
            name,
            path,
            sha256,
            arch,
            format,
            load,
            text,
            span,
        })
    }

    fn capture(&mut self, span: Span) -> Result<CaptureDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Eq)?;
        let kind = self.ident()?;
        if kind != "capture" {
            return Err(self.err(
                span,
                format!("capture must be `capture(...)`, found `{kind}`"),
            ));
        }
        let args = self.args()?;
        self.expect(Token::Semi)?;
        let path = self.need_pos_string(&args, 0, "capture path", span)?;
        let sha256 = self.need_string(&args, "sha256", "capture digest", span)?;
        validate_sha256(&sha256, &self.path, span)?;
        Ok(CaptureDecl {
            name,
            path,
            sha256,
            build: args.string("build"),
            filter: args.string("filter"),
            span,
        })
    }

    fn dump(&mut self, span: Span) -> Result<DumpDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Eq)?;
        let kind = self.ident()?;
        if kind != "dump" {
            return Err(self.err(span, format!("dump must be `dump(...)`, found `{kind}`")));
        }
        let args = self.args()?;
        self.expect(Token::Semi)?;
        let path = self.need_pos_string(&args, 0, "dump path", span)?;
        let sha256 = self.need_string(&args, "sha256", "dump digest", span)?;
        validate_sha256(&sha256, &self.path, span)?;
        let base = args.u64("base").ok_or_else(|| {
            self.err(
                span,
                "dump requires `base:` (the virtual address of file offset 0)",
            )
        })?;
        Ok(DumpDecl {
            name,
            path,
            sha256,
            base,
            build: args.string("build"),
            span,
        })
    }

    fn dataset(&mut self, span: Span) -> Result<DatasetDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Eq)?;
        let kind = self.ident()?;
        if kind != "dataset" {
            return Err(self.err(
                span,
                format!("dataset must be `dataset(...)`, found `{kind}`"),
            ));
        }
        let args = self.args()?;
        self.expect(Token::Semi)?;
        let path = self.need_pos_string(&args, 0, "dataset path", span)?;
        let sha256 = self.need_string(&args, "sha256", "dataset digest", span)?;
        validate_sha256(&sha256, &self.path, span)?;
        Ok(DatasetDecl {
            name,
            path,
            sha256,
            build: args.string("build"),
            from: args.string("from"),
            span,
        })
    }

    fn clock(&mut self, span: Span) -> Result<ClockDecl, String> {
        let name = self.ident()?;
        if !self.eat(Token::Eq) && !self.eat(Token::ColonEq) {
            return Err(self.err(self.span(), "expected `=` or `:=` in clock declaration"));
        }
        let kind = self.ident()?;
        let args = self.args()?;
        self.expect(Token::Semi)?;
        Ok(ClockDecl {
            name,
            kind,
            build: args.string("build").or_else(|| args.positional_string(0)),
            hz: args.f64("hz"),
            epoch: args.string("epoch"),
            monotone: args.bool("monotone").unwrap_or(true),
            span,
        })
    }

    fn relate(&mut self, span: Span) -> Result<RelateDecl, String> {
        let a = self.ident()?;
        if !self.eat(Token::Tilde) && !self.eat(Token::PlusMinus) {
            return Err(self.err(self.span(), "expected `~` in relate declaration"));
        }
        let b = self.ident()?;
        self.expect_ident("within")?;
        let d = self.value()?;
        let within_us = match d {
            Lit::Duration(us) => us,
            Lit::Int(n) => u64::try_from(n).map_err(|_| self.err(span, "invalid skew bound"))?,
            other => {
                return Err(self.err(
                    span,
                    format!("relate bound must be a duration, found {}", other.display()),
                ))
            }
        };
        self.expect(Token::Semi)?;
        Ok(RelateDecl {
            a,
            b,
            within_us,
            span,
        })
    }

    // ------------------------------------------------------------------
    // Model declarations
    // ------------------------------------------------------------------

    fn struct_decl(&mut self, span: Span) -> Result<StructDecl, String> {
        let name = self.ident()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect(Token::LBrace)?;
        let fields = self.fields()?;
        self.expect(Token::RBrace)?;
        self.expect_ident("size")?;
        let size = self.u64()?;
        self.expect_ident("align")?;
        let align = self.u64()?;
        self.expect(Token::Semi)?;
        Ok(StructDecl {
            name,
            build,
            fields,
            size,
            align,
            span,
        })
    }

    fn packet(&mut self, span: Span) -> Result<PacketDecl, String> {
        let name = self.ident()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect(Token::LBrace)?;
        let fields = self.fields()?;
        self.expect(Token::RBrace)?;
        self.expect_ident("size")?;
        let size = self.u64()?;
        self.expect(Token::Semi)?;
        Ok(PacketDecl {
            name,
            build,
            fields,
            size,
            span,
        })
    }

    fn fields(&mut self) -> Result<Vec<FieldDecl>, String> {
        let mut fields = Vec::new();
        while !self.at(Token::RBrace) {
            let span = self.span();
            let name = self.ident()?;
            self.expect(Token::Colon)?;
            let ty_ident = self.ident()?;
            let ty = match Ty::parse(&ty_ident) {
                Some(t) => FieldTy::Scalar(t),
                None => FieldTy::Named(ty_ident),
            };
            self.expect(Token::At)?;
            let offset = self.u64()?;
            let constant = if self.eat(Token::Eq) {
                let n = self.int()?;
                Some(n)
            } else {
                None
            };
            self.expect(Token::Semi)?;
            fields.push(FieldDecl {
                name,
                ty,
                offset,
                constant,
                span,
            });
        }
        Ok(fields)
    }

    fn fn_decl(&mut self, span: Span) -> Result<FnDecl, String> {
        let name = self.ident()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect_ident("at")?;
        let addr = self.u64()?;
        self.expect(Token::Semi)?;
        Ok(FnDecl {
            name,
            build,
            addr,
            span,
        })
    }

    fn rng_decl(&mut self, span: Span) -> Result<RngDecl, String> {
        let name = self.ident()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect_ident("at")?;
        let addr = self.u64()?;
        self.expect(Token::LBrace)?;
        let mut algo = None;
        let mut seed = None;
        let mut scope = None;
        while !self.at(Token::RBrace) {
            let key_span = self.span();
            let key = self.ident()?;
            self.expect(Token::Colon)?;
            match key.as_str() {
                "algo" => algo = Some(self.rng_algo()?),
                "seed" => seed = Some(self.raw_until_semi()),
                "scope" => scope = Some(self.raw_until_semi()),
                other => {
                    return Err(self.err(key_span, format!("unknown rng field `{other}`")));
                }
            }
            self.expect(Token::Semi)?;
        }
        self.expect(Token::RBrace)?;
        let algo = algo.ok_or_else(|| self.err(span, "rng declaration requires `algo:`"))?;
        Ok(RngDecl {
            name,
            build,
            addr,
            algo,
            seed,
            scope,
            span,
        })
    }

    fn rng_algo(&mut self) -> Result<RngAlgo, String> {
        let span = self.span();
        let name = self.ident()?;
        match name.to_ascii_uppercase().as_str() {
            "MT19937" => Ok(RngAlgo::Mt19937),
            "XORSHIFT32" => Ok(RngAlgo::XorShift32),
            "XORSHIFT128" => Ok(RngAlgo::XorShift128),
            "LCG" => {
                let args = self.args()?;
                let m = args
                    .u64("m")
                    .ok_or_else(|| self.err(span, "LCG requires `m:`"))?;
                let a = args
                    .u64("a")
                    .ok_or_else(|| self.err(span, "LCG requires `a:`"))?;
                let c = args
                    .u64("c")
                    .ok_or_else(|| self.err(span, "LCG requires `c:`"))?;
                Ok(RngAlgo::Lcg { m, a, c })
            }
            other => Ok(RngAlgo::Other(other.to_string())),
        }
    }

    fn dist_decl(&mut self, span: Span) -> Result<DistDecl, String> {
        let name = self.ident()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect(Token::LBrace)?;
        let mut rng = None;
        let mut site = None;
        let mut bins = None;
        while !self.at(Token::RBrace) {
            let key_span = self.span();
            let key = self.ident()?;
            self.expect(Token::Colon)?;
            match key.as_str() {
                "rng" => rng = Some(self.ref_name()?),
                "site" => site = Some(self.ref_name()?),
                "bins" => bins = Some(self.u64()?),
                other => {
                    return Err(self.err(key_span, format!("unknown dist field `{other}`")));
                }
            }
            self.expect(Token::Semi)?;
        }
        self.expect(Token::RBrace)?;
        Ok(DistDecl {
            name,
            build,
            rng: rng.ok_or_else(|| self.err(span, "dist requires `rng:`"))?,
            site: site.ok_or_else(|| self.err(span, "dist requires `site:`"))?,
            bins: bins.ok_or_else(|| self.err(span, "dist requires `bins:`"))?,
            span,
        })
    }

    // ------------------------------------------------------------------
    // Evidence
    // ------------------------------------------------------------------

    fn evidence(&mut self, span: Span) -> Result<EvidenceDecl, String> {
        let name = self.ident()?;
        self.expect(Token::ColonEq)?;
        let kind_name = self.ident()?;
        let args = self.args()?;
        let mut modifiers = Vec::new();
        while self.eat(Token::PipeGt) {
            let m = self.ident()?;
            modifiers.push(m);
        }
        self.expect(Token::Semi)?;

        let kind = match kind_name.as_str() {
            "scan" => {
                let build = self.need_pos_string(&args, 0, "scan build", span)?;
                let section = self.need_pos_string(&args, 1, "scan section", span)?;
                let pattern = self.need_pos_string(&args, 2, "scan pattern", span)?;
                EvidenceKind::Scan {
                    build,
                    section,
                    pattern,
                }
            }
            "bytes" => {
                let artifact = self.need_pos_string(&args, 0, "bytes artifact", span)?;
                let at = args
                    .u64("at")
                    .or_else(|| args.positional_u64(1))
                    .ok_or_else(|| self.err(span, "bytes requires `at:`"))?;
                let expect = self.need_string(&args, "expect", "expected bytes", span)?;
                EvidenceKind::Bytes {
                    artifact,
                    at,
                    expect,
                }
            }
            "decode" => {
                let build = self.need_pos_string(&args, 0, "decode build", span)?;
                let func = self.need_pos_string(&args, 1, "decode function", span)?;
                let count = args.u64("count").unwrap_or(8) as usize;
                EvidenceKind::Decode { build, func, count }
            }
            "constants" => {
                let build = self.need_pos_string(&args, 0, "constants build", span)?;
                let at = self.need_target(&args, "at", span)?;
                let window = args.u64("window").unwrap_or(256);
                let values = args
                    .list("values")
                    .ok_or_else(|| self.err(span, "constants requires `values: [...]`"))?
                    .iter()
                    .map(|l| match l {
                        Lit::Int(n) => Ok(*n as u32),
                        other => Err(self.err(
                            span,
                            format!("constant must be an integer, found {}", other.display()),
                        )),
                    })
                    .collect::<Result<Vec<u32>, String>>()?;
                let unique = modifiers.iter().any(|m| m == "unique");
                EvidenceKind::Constants {
                    build,
                    at,
                    window,
                    values,
                    unique,
                }
            }
            "modulo" => {
                let build = self.need_pos_string(&args, 0, "modulo build", span)?;
                let func = self.need_pos_string(&args, 1, "modulo function", span)?;
                let modulus = args
                    .u64("modulus")
                    .ok_or_else(|| self.err(span, "modulo requires `modulus:`"))?;
                if modulus == 0 {
                    return Err(self.err(span, "modulus must be non-zero"));
                }
                EvidenceKind::Modulo {
                    build,
                    func,
                    modulus,
                }
            }
            "recovery" => {
                let rng = self.need_pos_string(&args, 0, "recovery rng", span)?;
                let state = self.need_string(&args, "state", "state dataset", span)?;
                let index = args
                    .u64("index")
                    .ok_or_else(|| self.err(span, "recovery requires `index:`"))?;
                let observed = self.need_string(&args, "observed", "observed dataset", span)?;
                let projection = args
                    .string("projection")
                    .unwrap_or_else(|| "full32".to_string());
                let algo = match args.get("algo") {
                    None => None,
                    Some(ArgVal::Lit(Lit::Sym(s))) | Some(ArgVal::Lit(Lit::Str(s))) => {
                        Some(parse_algo_name(s).ok_or_else(|| {
                            self.err(span, format!("unsupported recovery algorithm `{s}`"))
                        })?)
                    }
                    Some(other) => {
                        return Err(self.err(
                            span,
                            format!("algo expects a name, found {}", other.display()),
                        ))
                    }
                };
                EvidenceKind::Recovery {
                    rng,
                    algo,
                    state,
                    index,
                    observed,
                    projection,
                }
            }
            "rate" => {
                let capture = self.need_pos_string(&args, 0, "rate capture", span)?;
                let opcode = args
                    .u64("opcode")
                    .ok_or_else(|| self.err(span, "rate requires `opcode:`"))?;
                if opcode > 0xffff {
                    return Err(self.err(span, "opcode must fit in u16"));
                }
                EvidenceKind::Rate {
                    capture,
                    opcode: opcode as u16,
                    clock: args.string("clock"),
                }
            }
            "sample" => {
                let capture = self.need_pos_string(&args, 0, "sample capture", span)?;
                let opcode = args
                    .u64("opcode")
                    .ok_or_else(|| self.err(span, "sample requires `opcode:`"))?;
                if opcode > 0xffff {
                    return Err(self.err(span, "opcode must fit in u16"));
                }
                let field = args
                    .u64("field")
                    .ok_or_else(|| self.err(span, "sample requires `field:`"))?
                    as usize;
                let width = args
                    .u64("width")
                    .ok_or_else(|| self.err(span, "sample requires `width:`"))?
                    as usize;
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return Err(self.err(span, "sample width must be 1, 2, 4, or 8"));
                }
                let endian = args.string("endian").unwrap_or_else(|| "be".to_string());
                let big_endian = match endian.as_str() {
                    "be" | "big" => true,
                    "le" | "little" => false,
                    other => {
                        return Err(self.err(span, format!("unknown endian `{other}`")));
                    }
                };
                EvidenceKind::Sample {
                    capture,
                    opcode: opcode as u16,
                    field,
                    width,
                    big_endian,
                }
            }
            "external" => {
                let path = self.need_pos_string(&args, 0, "certificate path", span)?;
                let kind = self.need_string(&args, "kind", "certificate kind", span)?;
                let build = self.need_string(&args, "build", "certificate build", span)?;
                EvidenceKind::External { path, kind, build }
            }
            "samples" => {
                let dataset = self.need_pos_string(&args, 0, "samples dataset", span)?;
                let value_col = args
                    .u64("value")
                    .ok_or_else(|| self.err(span, "samples requires `value:`"))?
                    as usize;
                let group_col = args.u64("group").map(|g| g as usize);
                let delim = args.string("delim").unwrap_or_else(|| "csv".to_string());
                if !matches!(delim.as_str(), "csv" | "tsv" | "ws") {
                    return Err(self.err(
                        span,
                        format!("unknown delimiter `{delim}` (expected csv, tsv, or ws)"),
                    ));
                }
                EvidenceKind::Samples {
                    dataset,
                    value_col,
                    group_col,
                    delim,
                }
            }
            "symbols" => {
                let build = self.need_pos_string(&args, 0, "symbols build", span)?;
                let path = self.need_pos_string(&args, 1, "symbols path", span)?;
                EvidenceKind::Symbols { build, path }
            }
            "absence" => {
                let path = self.need_pos_string(&args, 0, "absence certificate", span)?;
                let build = self.need_string(&args, "build", "absence build", span)?;
                let scope = self.need_string(&args, "scope", "absence scope", span)?;
                let during = self.need_string(&args, "during", "absence capture", span)?;
                EvidenceKind::Absence {
                    path,
                    build,
                    scope,
                    during,
                }
            }
            "table" => {
                let dataset = self.need_pos_string(&args, 0, "table dataset", span)?;
                let format = match args.string("format") {
                    Some(f) => {
                        let f = f.trim().to_ascii_lowercase();
                        if !matches!(f.as_str(), "csv" | "tsv" | "ws") {
                            return Err(self.err(
                                span,
                                format!(
                                    "table format must be \"csv\", \"tsv\", or \"ws\", found {f:?}"
                                ),
                            ));
                        }
                        f
                    }
                    None => "csv".to_string(),
                };
                let has_header = args.bool("has_header").unwrap_or(false);
                EvidenceKind::Table {
                    dataset,
                    format,
                    has_header,
                }
            }
            other => EvidenceKind::Extension {
                kind: other.to_string(),
                args,
            },
        };

        Ok(EvidenceDecl {
            name,
            kind,
            modifiers,
            span,
        })
    }

    // ------------------------------------------------------------------
    // Rules, proofs, claims
    // ------------------------------------------------------------------

    fn rule(&mut self, span: Span) -> Result<RuleDecl, String> {
        let name = self.ident()?;
        let cap = if self.eat_ident("cap") {
            Some(self.strength()?)
        } else {
            None
        };
        self.expect(Token::Colon)?;
        let head = self.atom()?;
        self.expect_ident("if")?;
        let mut body = vec![self.atom()?];
        while self.eat(Token::And) {
            body.push(self.atom()?);
        }
        self.expect(Token::Semi)?;
        Ok(RuleDecl {
            name,
            head,
            body,
            cap,
            span,
        })
    }

    fn proof(&mut self, span: Span) -> Result<ProofDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Colon)?;
        let goal = self.atom()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect(Token::LBrace)?;
        let mut evidence = Vec::new();
        let mut rules = Vec::new();
        let mut expect = None;
        while !self.at(Token::RBrace) {
            let line_span = self.span();
            let key = self.ident()?;
            match key.as_str() {
                "evidence" => {
                    evidence.extend(self.name_list()?);
                    self.expect(Token::Semi)?;
                }
                "rules" => {
                    rules.extend(self.name_list()?);
                    self.expect(Token::Semi)?;
                }
                "expect" => {
                    self.expect(Token::Ge)?;
                    expect = Some(self.strength()?);
                    self.expect(Token::Semi)?;
                }
                "note" => {
                    // A free-form comment kept in the source for humans.
                    let _ = self.advance();
                    self.expect(Token::Semi)?;
                }
                other => return Err(self.err(line_span, format!("unknown proof clause `{other}`"))),
            }
        }
        self.expect(Token::RBrace)?;
        Ok(ProofDecl {
            name,
            goal,
            build,
            evidence,
            rules,
            expect,
            span,
        })
    }

    fn claim(&mut self, span: Span) -> Result<ClaimDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Colon)?;
        let head_span = self.span();
        let head_name = self.ident()?;
        let head = match head_name.as_str() {
            "period" | "tick_rate" => {
                self.expect(Token::LParen)?;
                let clock = self.ident()?;
                self.expect(Token::Comma)?;
                self.expect_ident("stream")?;
                self.expect(Token::Colon)?;
                let stream = self.u64()?;
                if stream > 0xffff {
                    return Err(self.err(head_span, "stream opcode must fit in u16"));
                }
                self.expect(Token::RParen)?;
                self.expect(Token::Tilde)?;
                let period_us = self.duration()?;
                self.expect(Token::PlusMinus)?;
                let eps_us = self.duration()?;
                ClaimHead::Period {
                    clock,
                    stream: stream as u16,
                    period_us,
                    eps_us,
                }
            }
            "uniform" => {
                self.expect(Token::LParen)?;
                let dist = self.ident()?;
                self.expect(Token::Comma)?;
                self.expect_ident("bins")?;
                self.expect(Token::Colon)?;
                let bins = self.u64()?;
                self.expect(Token::RParen)?;
                ClaimHead::Uniform { dist, bins }
            }
            "mean" => {
                self.expect(Token::LParen)?;
                // The metric is a group symbol from `samples` evidence. A
                // string is accepted so a group-less evidence term (whose
                // single group is named "") can be claimed as mean("").
                let metric = match self.peek().clone() {
                    Token::Ident(_) => self.ident()?,
                    Token::Str(_) => self.string()?,
                    other => {
                        return Err(self.err(
                            head_span,
                            format!("expected a metric name, found {}", other.describe()),
                        ))
                    }
                };
                self.expect(Token::RParen)?;
                self.expect(Token::Tilde)?;
                let value = self.float()?;
                self.expect(Token::PlusMinus)?;
                let eps = self.float()?;
                ClaimHead::Mean { metric, value, eps }
            }
            "coverage" => {
                self.expect(Token::LParen)?;
                let dataset = self.ident()?;
                self.expect(Token::Comma)?;
                self.expect_ident("target")?;
                self.expect(Token::Colon)?;
                let target = self.u64()?;
                self.expect(Token::RParen)?;
                ClaimHead::Coverage { dataset, target }
            }
            _ => ClaimHead::Rel(self.atom_from(head_name)?),
        };
        self.expect_ident("in")?;
        let build = self.ident()?;
        let during = if self.eat_ident("during") {
            Some(self.ident()?)
        } else {
            None
        };
        let provisional_until = if self.eat_ident("provisional") {
            self.expect_ident("until")?;
            let v = match self.advance().token.clone() {
                Token::Str(s) => s,
                Token::Ident(s) => s,
                other => {
                    return Err(self.err(
                        self.span(),
                        format!("expected a date string, found {}", other.describe()),
                    ))
                }
            };
            Some(v)
        } else {
            None
        };
        let body = if self.eat_ident("by") {
            let evidence = self.ident()?;
            let mut requires = Vec::new();
            if self.eat_ident("require") {
                loop {
                    requires.push(self.requirement()?);
                    if !self.eat(Token::Comma) {
                        break;
                    }
                }
            }
            ClaimBody::Direct { evidence, requires }
        } else if self.eat_ident("from") {
            let from = self.name_list()?;
            if matches!(&head, ClaimHead::Coverage { .. }) {
                ClaimBody::Coverage { from }
            } else {
                ClaimBody::Derived { from }
            }
        } else {
            return Err(self.err(
                self.span(),
                "claim requires `by <evidence>` or `from <claim,...>`",
            ));
        };
        self.expect(Token::Semi)?;
        Ok(ClaimDecl {
            name,
            head,
            build,
            during,
            body,
            provisional_until,
            span,
        })
    }

    fn requirement(&mut self) -> Result<Requirement, String> {
        let span = self.span();
        let key = self.ident()?;
        match key.as_str() {
            "coverage" => {
                self.expect(Token::Ge)?;
                Ok(Requirement::CoverageAtLeast(self.duration()?))
            }
            "alpha" => {
                if !self.eat(Token::Colon) {
                    self.expect(Token::Eq)?;
                }
                Ok(Requirement::Alpha(self.float()?))
            }
            "power" => {
                if !self.eat(Token::Colon) {
                    self.expect(Token::Eq)?;
                }
                Ok(Requirement::Power(self.float()?))
            }
            "delta" => {
                if !self.eat(Token::Colon) {
                    self.expect(Token::Eq)?;
                }
                Ok(Requirement::Delta(self.float()?))
            }
            "confidence" => {
                self.expect(Token::Ge)?;
                Ok(Requirement::ConfidenceAtLeast(self.float()?))
            }
            "samples" => {
                self.expect(Token::Ge)?;
                Ok(Requirement::SamplesAtLeast(self.u64()?))
            }
            other => Err(self.err(span, format!("unknown claim requirement `{other}`"))),
        }
    }

    fn conflict(&mut self, span: Span) -> Result<ConflictDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Colon)?;
        let left = self.ident()?;
        self.expect_ident("vs")?;
        let right = self.ident()?;
        let mut prefer = None;
        let mut decision = None;
        let mut reason = None;
        while !self.at(Token::Semi) {
            if self.eat_ident("prefer") {
                if prefer.is_some() {
                    return Err(self.err(span, format!("conflict {name} has duplicate `prefer`")));
                }
                prefer = Some(self.ident()?);
            } else if self.eat_ident("decision") {
                if decision.is_some() {
                    return Err(self.err(span, format!("conflict {name} has duplicate `decision`")));
                }
                decision = Some(self.ident()?);
            } else if self.eat_ident("reason") {
                if reason.is_some() {
                    return Err(self.err(span, format!("conflict {name} has duplicate `reason`")));
                }
                reason = Some(self.string()?);
            } else {
                return Err(self.err(
                    self.span(),
                    format!(
                        "expected `prefer`, `decision`, or `reason`, found {}",
                        self.peek().describe()
                    ),
                ));
            }
        }
        if prefer.is_some() && decision.is_some() {
            return Err(self.err(
                span,
                format!("conflict {name} has both prefer and decision"),
            ));
        }
        self.expect(Token::Semi)?;
        Ok(ConflictDecl {
            name,
            left,
            right,
            prefer,
            decision,
            reason,
            span,
        })
    }

    fn decision(&mut self, span: Span) -> Result<DecisionDecl, String> {
        let name = self.ident()?;
        self.expect(Token::ColonEq)?;
        let kind = self.ident()?;
        if kind != "decision" {
            return Err(self.err(
                span,
                format!("decision must be `decision(...)`, found `{kind}`"),
            ));
        }
        let args = self.args()?;
        self.expect(Token::Semi)?;
        let path = self.need_pos_string(&args, 0, "decision path", span)?;
        let sha256 = self.need_string(&args, "sha256", "decision digest", span)?;
        validate_sha256(&sha256, &self.path, span)?;
        let prefer = self.need_string(&args, "prefer", "preferred claim", span)?;
        let over = self.need_string(&args, "over", "overridden claim", span)?;
        let signer = args.string("signer");
        Ok(DecisionDecl {
            name,
            path,
            sha256,
            prefer,
            over,
            signer,
            span,
        })
    }

    fn obligation(&mut self, span: Span) -> Result<ObligationDecl, String> {
        let name = self.ident()?;
        if self.eat_ident("resolved") {
            self.expect_ident("by")?;
            let claimant = self.ident()?;
            self.expect(Token::Semi)?;
            return Ok(ObligationDecl {
                name,
                atom: Atom {
                    name: "resolved".into(),
                    args: Vec::new(),
                    span,
                },
                priority: Priority::Medium,
                blocks_seal: false,
                resolved_by: Some(claimant),
                span,
            });
        }
        self.expect(Token::Colon)?;
        let atom = self.atom()?;
        self.expect_ident("priority")?;
        self.expect(Token::Colon)?;
        let p = self.ident()?;
        let priority =
            Priority::parse(&p).ok_or_else(|| self.err(span, format!("unknown priority `{p}`")))?;
        let blocks_seal = if self.eat_ident("blocks") {
            self.expect(Token::Colon)?;
            let what = self.ident()?;
            if what != "seal" {
                return Err(self.err(span, format!("unknown block target `{what}`")));
            }
            true
        } else {
            false
        };
        self.expect(Token::Semi)?;
        Ok(ObligationDecl {
            name,
            atom,
            priority,
            blocks_seal,
            resolved_by: None,
            span,
        })
    }

    fn refute(&mut self, span: Span) -> Result<RefuteDecl, String> {
        let name = self.ident()?;
        self.expect(Token::Colon)?;
        let goal = self.atom()?;
        self.expect_ident("in")?;
        let build = self.ident()?;
        self.expect_ident("by")?;
        let evidence = self.ident()?;
        self.expect(Token::Semi)?;
        Ok(RefuteDecl {
            name,
            goal,
            build,
            evidence,
            span,
        })
    }

    fn port(&mut self, span: Span) -> Result<PortDecl, String> {
        self.expect_ident("from")?;
        let from = self.ident()?;
        self.expect_ident("to")?;
        let to = self.ident()?;
        self.expect(Token::LBrace)?;
        let mut rules = Vec::new();
        while !self.at(Token::RBrace) {
            let rule_span = self.span();
            let key = self.ident()?;
            match key.as_str() {
                "rebase" => {
                    let target = self.ident()?;
                    self.expect_ident("by")?;
                    self.expect_ident("structural_similarity")?;
                    self.expect(Token::LParen)?;
                    let window = self.u64()?;
                    self.expect(Token::RParen)?;
                    let min_similarity = if self.eat_ident("min") {
                        self.float()?
                    } else {
                        0.55
                    };
                    self.expect(Token::Semi)?;
                    rules.push(PortRule::Rebase {
                        target,
                        window,
                        min_similarity,
                    });
                }
                "drop" => {
                    let target = self.ident()?;
                    self.expect(Token::Semi)?;
                    rules.push(PortRule::Drop { target });
                }
                "revalidate" => {
                    let evidence = self.ident()?;
                    self.expect_ident("with")?;
                    let with = self.ident()?;
                    self.expect(Token::Semi)?;
                    rules.push(PortRule::Revalidate { evidence, with });
                }
                other => return Err(self.err(rule_span, format!("unknown port rule `{other}`"))),
            }
        }
        self.expect(Token::RBrace)?;
        Ok(PortDecl {
            from,
            to,
            rules,
            span,
        })
    }

    // ------------------------------------------------------------------
    // Shared productions
    // ------------------------------------------------------------------

    fn args(&mut self) -> Result<Args, String> {
        self.expect(Token::LParen)?;
        let mut positional = Vec::new();
        let mut named = std::collections::BTreeMap::new();
        if self.eat(Token::RParen) {
            return Ok(Args { positional, named });
        }
        loop {
            let start = self.span();
            let saved = self.pos;
            let name = if let Token::Ident(id) = self.peek().clone() {
                let next = self.tokens.get(self.pos + 1).map(|t| &t.token);
                if matches!(next, Some(Token::Colon)) {
                    self.pos += 2;
                    Some(id)
                } else {
                    self.pos = saved;
                    None
                }
            } else {
                None
            };
            let value = self.arg_value()?;
            if let Some(name) = name {
                if named.insert(name.clone(), value).is_some() {
                    return Err(self.err(start, format!("duplicate argument `{name}`")));
                }
            } else {
                positional.push(value);
            }
            if self.eat(Token::Comma) {
                continue;
            }
            self.expect(Token::RParen)?;
            break;
        }
        Ok(Args { positional, named })
    }

    fn arg_value(&mut self) -> Result<ArgVal, String> {
        if let Token::Int(n) = self.peek().clone() {
            let after = self.tokens.get(self.pos + 1).map(|t| &t.token);
            if matches!(after, Some(Token::DotDot)) {
                self.pos += 2;
                let end = self.u64()?;
                let start = u64::try_from(n)
                    .map_err(|_| self.err(self.span(), "range start must be non-negative"))?;
                return Ok(ArgVal::Range(start, end));
            }
        }
        Ok(ArgVal::Lit(self.value()?))
    }

    fn value(&mut self) -> Result<Lit, String> {
        let span = self.span();
        match self.peek().clone() {
            Token::Int(n) => {
                self.pos += 1;
                // A duration is an integer or float followed by a unit.
                if let Token::Ident(unit) = self.peek().clone() {
                    if let Some(mult) = duration_unit(&unit) {
                        self.pos += 1;
                        let us = (n as f64 * mult).round();
                        if us < 0.0 {
                            return Err(self.err(span, "negative duration"));
                        }
                        return Ok(Lit::Duration(us as u64));
                    }
                }
                Ok(Lit::Int(n))
            }
            Token::Float(v) => {
                self.pos += 1;
                if let Token::Ident(unit) = self.peek().clone() {
                    if let Some(mult) = duration_unit(&unit) {
                        self.pos += 1;
                        let us = (v * mult).round();
                        if us < 0.0 {
                            return Err(self.err(span, "negative duration"));
                        }
                        return Ok(Lit::Duration(us as u64));
                    }
                }
                Ok(Lit::Float(v))
            }
            Token::Str(s) => {
                self.pos += 1;
                Ok(Lit::Str(s))
            }
            Token::Minus => {
                self.pos += 1;
                match self.peek().clone() {
                    Token::Int(n) => {
                        self.pos += 1;
                        Ok(Lit::Int(-n))
                    }
                    Token::Float(v) => {
                        self.pos += 1;
                        Ok(Lit::Float(-v))
                    }
                    other => Err(self.err(
                        span,
                        format!("expected a number after `-`, found {}", other.describe()),
                    )),
                }
            }
            Token::LBracket => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.eat(Token::RBracket) {
                    return Ok(Lit::List(items));
                }
                loop {
                    items.push(self.value()?);
                    if self.eat(Token::Comma) {
                        continue;
                    }
                    self.expect(Token::RBracket)?;
                    break;
                }
                Ok(Lit::List(items))
            }
            Token::Ident(id) => {
                self.pos += 1;
                if id == "true" {
                    return Ok(Lit::Bool(true));
                }
                if id == "false" {
                    return Ok(Lit::Bool(false));
                }
                if id == "LCG" && self.at(Token::LParen) {
                    // Encode LCG(...) as a symbol so rng parsing can re-read it.
                    let args = self.args()?;
                    let parts: Vec<String> = args
                        .named
                        .iter()
                        .map(|(k, v)| format!("{k}:{}", v.display()))
                        .collect();
                    return Ok(Lit::Sym(format!("LCG({})", parts.join(","))));
                }
                let mut name = id;
                while self.eat(Token::Dot) {
                    let part = self.ident()?;
                    name.push('.');
                    name.push_str(&part);
                }
                Ok(Lit::Sym(name))
            }
            other => Err(self.err(
                span,
                format!("expected a value, found {}", other.describe()),
            )),
        }
    }

    fn atom(&mut self) -> Result<Atom, String> {
        let name = self.ident()?;
        self.atom_from(name)
    }

    fn atom_from(&mut self, name: String) -> Result<Atom, String> {
        let span = self.span();
        self.expect(Token::LParen)?;
        let mut args = Vec::new();
        if !self.eat(Token::RParen) {
            loop {
                args.push(self.term()?);
                if self.eat(Token::Comma) {
                    continue;
                }
                self.expect(Token::RParen)?;
                break;
            }
        }
        Ok(Atom { name, args, span })
    }

    fn term(&mut self) -> Result<Term, String> {
        if self.eat(Token::Question) {
            let name = self.ident()?;
            return Ok(Term::Var(name));
        }
        Ok(Term::Lit(self.value()?))
    }

    fn name_list(&mut self) -> Result<Vec<String>, String> {
        let mut out = vec![self.ident()?];
        while self.eat(Token::Comma) {
            out.push(self.ident()?);
        }
        Ok(out)
    }

    fn duration(&mut self) -> Result<u64, String> {
        let span = self.span();
        match self.value()? {
            Lit::Duration(us) => Ok(us),
            Lit::Int(n) => {
                u64::try_from(n).map_err(|_| self.err(span, "duration must be non-negative"))
            }
            other => Err(self.err(
                span,
                format!(
                    "expected a duration (for example 50ms), found {}",
                    other.display()
                ),
            )),
        }
    }

    fn strength(&mut self) -> Result<Strength, String> {
        let span = self.span();
        let s = self.ident()?;
        Strength::parse(&s).ok_or_else(|| self.err(span, format!("unknown strength `{s}`")))
    }

    fn need_target(&mut self, args: &Args, key: &str, span: Span) -> Result<Target, String> {
        match args.get(key) {
            Some(ArgVal::Lit(Lit::Int(n))) => Ok(Target::Addr(
                u64::try_from(*n).map_err(|_| self.err(span, "negative address"))?,
            )),
            Some(ArgVal::Lit(Lit::Sym(s))) => Ok(Target::Ref(s.clone())),
            Some(other) => Err(self.err(
                span,
                format!(
                    "`{key}:` expects an address or a reference, found {}",
                    other.display()
                ),
            )),
            None => Err(self.err(span, format!("missing required argument `{key}:`"))),
        }
    }

    fn need_pos_string(
        &mut self,
        args: &Args,
        i: usize,
        what: &str,
        span: Span,
    ) -> Result<String, String> {
        args.positional_string(i)
            .ok_or_else(|| self.err(span, format!("missing {what}")))
    }

    fn need_string(
        &mut self,
        args: &Args,
        key: &str,
        what: &str,
        span: Span,
    ) -> Result<String, String> {
        args.string(key)
            .ok_or_else(|| self.err(span, format!("missing {what} (`{key}:`)")))
    }

    fn raw_until_semi(&mut self) -> String {
        let mut parts = Vec::new();
        while !self.at(Token::Semi) && !self.at(Token::Eof) {
            let tok = self.advance().token.clone();
            parts.push(match tok {
                Token::Ident(s) => s,
                Token::Int(n) => n.to_string(),
                Token::Float(v) => v.to_string(),
                Token::Str(s) => format!("{s:?}"),
                Token::Colon => ":".into(),
                Token::Comma => ",".into(),
                Token::LParen => "(".into(),
                Token::RParen => ")".into(),
                Token::At => "@".into(),
                Token::Dot => ".".into(),
                Token::Question => "?".into(),
                Token::Eq => "=".into(),
                Token::PlusMinus => "+-".into(),
                Token::Tilde => "~".into(),
                other => other.describe(),
            });
        }
        parts.join(" ")
    }

    fn ref_name(&mut self) -> Result<String, String> {
        let mut name = self.ident()?;
        while self.eat(Token::Dot) {
            name.push('.');
            name.push_str(&self.ident()?);
        }
        Ok(name)
    }

    // ------------------------------------------------------------------
    // Token helpers
    // ------------------------------------------------------------------

    fn peek(&self) -> &Token {
        &self.tokens[self.pos].token
    }

    fn span(&self) -> Span {
        self.tokens[self.pos].span
    }

    fn advance(&mut self) -> &TokenWithSpan {
        let t = &self.tokens[self.pos];
        if !matches!(t.token, Token::Eof) {
            self.pos += 1;
        }
        t
    }

    fn at(&self, tok: Token) -> bool {
        std::mem::discriminant(self.peek()) == std::mem::discriminant(&tok)
    }

    fn eat(&mut self, tok: Token) -> bool {
        if self.at(tok.clone()) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, tok: Token) -> Result<(), String> {
        if self.eat(tok.clone()) {
            Ok(())
        } else {
            Err(self.err(
                self.span(),
                format!(
                    "expected {}, found {}",
                    tok.describe(),
                    self.peek().describe()
                ),
            ))
        }
    }

    fn eat_ident(&mut self, s: &str) -> bool {
        if matches!(self.peek(), Token::Ident(x) if x == s) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self, s: &str) -> Result<(), String> {
        if self.eat_ident(s) {
            Ok(())
        } else {
            Err(self.err(
                self.span(),
                format!("expected `{s}`, found {}", self.peek().describe()),
            ))
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        match self.peek().clone() {
            Token::Ident(s) => {
                self.advance();
                Ok(s)
            }
            other => Err(self.err(
                self.span(),
                format!("expected an identifier, found {}", other.describe()),
            )),
        }
    }

    fn int(&mut self) -> Result<i128, String> {
        match self.peek().clone() {
            Token::Int(n) => {
                self.advance();
                Ok(n)
            }
            other => Err(self.err(
                self.span(),
                format!("expected an integer, found {}", other.describe()),
            )),
        }
    }

    fn u64(&mut self) -> Result<u64, String> {
        let span = self.span();
        let n = self.int()?;
        u64::try_from(n).map_err(|_| self.err(span, "expected a non-negative integer"))
    }

    fn float(&mut self) -> Result<f64, String> {
        let span = self.span();
        match self.peek().clone() {
            Token::Float(v) => {
                self.advance();
                Ok(v)
            }
            Token::Int(n) => {
                self.advance();
                Ok(n as f64)
            }
            other => Err(self.err(
                span,
                format!("expected a number, found {}", other.describe()),
            )),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        let span = self.span();
        match self.peek().clone() {
            Token::Str(s) => {
                self.advance();
                Ok(s)
            }
            other => Err(self.err(
                span,
                format!("expected a string, found {}", other.describe()),
            )),
        }
    }

    fn err(&self, span: Span, msg: impl Into<String>) -> String {
        format!("{}:{}: {}", self.path, span, msg.into())
    }
}

fn duration_unit(unit: &str) -> Option<f64> {
    match unit {
        "us" | "µs" => Some(1.0),
        "ms" => Some(1_000.0),
        "s" => Some(1_000_000.0),
        "m" | "min" => Some(60_000_000.0),
        "h" => Some(3_600_000_000.0),
        "d" => Some(86_400_000_000.0),
        _ => None,
    }
}

fn parse_algo_name(s: &str) -> Option<RngAlgo> {
    match s.to_ascii_uppercase().as_str() {
        "MT19937" => Some(RngAlgo::Mt19937),
        "XORSHIFT32" => Some(RngAlgo::XorShift32),
        "XORSHIFT128" => Some(RngAlgo::XorShift128),
        "LCG" => Some(RngAlgo::Other("LCG".into())),
        _ => None,
    }
}

fn validate_sha256(s: &str, path: &str, span: Span) -> Result<(), String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{path}:{span}: sha256 must be 64 hex characters, found {:?}",
            s
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINI: &str = r#"
        build b1 = binary("game.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64, load: 0x140000000, text: 0x140001000..0x140002000);
        struct Vec3 in b1 { x: f32 @ 0; y: f32 @ 4; z: f32 @ 8; } size 12 align 4;
        fn read_position in b1 at 0x140001000;
        ev e_scan := scan(b1, ".text", "F3 0F 10 47 ??") |> unique;
        rule r1: reads(?f, ?field) if field_offset(?field, ?o) and loads_set(?e, ?f, ?offs, 4) and contains(?offs, ?o);
        proof P: reads(read_position, Vec3.z) in b1 { evidence e_scan; rules r1; expect >= deterministic; }
        claim C: uniform(LootTable, bins: 12) in b1 during c1 by e_loot require alpha: 1e-4, power: 0.999, delta: 0.02, coverage >= 100s;
    "#;

    #[test]
    fn parses_a_model() {
        let m = parse_model("test.dg", MINI).unwrap();
        assert_eq!(m.items.len(), 7);
    }

    #[test]
    fn rejects_bad_digest() {
        let src = r#"build b = binary("x", sha256: "abc", arch: x86_64);"#;
        assert!(parse_model("t.dg", src).is_err());
    }

    #[test]
    fn accepts_unicode_aliases() {
        let src = r#"
            claim C : period(srv, stream: 0x1F4) ≈ 15625us ± 300us in b1 during c1
              by e_tick require coverage ≥ 60s;
        "#;
        let m = parse_model("t.dg", src).unwrap();
        match &m.items[0] {
            Item::Claim(c) => assert!(matches!(c.head, ClaimHead::Period { .. })),
            _ => panic!("wrong item"),
        }
    }

    #[test]
    fn parses_port_rules() {
        let src = r#"port from b1 to b2 { rebase read_position by structural_similarity(64) min 0.6; drop e_old; }"#;
        let m = parse_model("t.dg", src).unwrap();
        assert!(matches!(m.items[0], Item::Port(_)));
    }

    #[test]
    fn parses_samples_evidence_and_mean_claim() {
        let src = r#"
            build b1 = binary("g.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64);
            dataset ds = dataset("s.csv", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", build: b1);
            ev e := samples(ds, value: 0, group: 1, delim: "csv");
            claim C : mean(atk_damage) ~ 42.5 ± 1.2 in b1
              by e require samples >= 200, confidence >= 0.95, power: 0.8, delta: 2.0;
        "#;
        let m = parse_model("t.dg", src).unwrap();
        match &m.items[2] {
            Item::Evidence(ev) => match &ev.kind {
                EvidenceKind::Samples {
                    dataset,
                    value_col,
                    group_col,
                    delim,
                } => {
                    assert_eq!(dataset, "ds");
                    assert_eq!(*value_col, 0);
                    assert_eq!(*group_col, Some(1));
                    assert_eq!(delim, "csv");
                }
                other => panic!("wrong evidence kind: {other:?}"),
            },
            other => panic!("wrong item: {other:?}"),
        }
        match &m.items[3] {
            Item::Claim(c) => match &c.head {
                ClaimHead::Mean { metric, value, eps } => {
                    assert_eq!(metric, "atk_damage");
                    assert!((*value - 42.5).abs() < 1e-9);
                    assert!((*eps - 1.2).abs() < 1e-9);
                }
                other => panic!("wrong claim head: {other:?}"),
            },
            other => panic!("wrong item: {other:?}"),
        }
    }

    #[test]
    fn parses_coverage_claim() {
        let src = r#"
            build b1 = binary("g.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64);
            claim C : coverage(ds_ids, target: 82) in b1 from P_1, P_2;
        "#;
        let m = parse_model("t.dg", src).unwrap();
        match &m.items[1] {
            Item::Claim(c) => {
                assert!(matches!(
                    &c.head,
                    ClaimHead::Coverage {
                        dataset,
                        target: 82
                    } if dataset == "ds_ids"
                ));
                assert!(matches!(
                    &c.body,
                    ClaimBody::Coverage { from } if from == &["P_1".to_string(), "P_2".to_string()]
                ));
            }
            other => panic!("wrong item: {other:?}"),
        }
    }

    #[test]
    fn parses_conflict_with_decision_and_decision_decl() {
        let src = r#"
            conflict C : A vs B decision D reason "see the decision file";
            decision D := decision("decisions/d.txt", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", prefer: A, over: B, signer: "auditor");
        "#;
        let m = parse_model("t.dg", src).unwrap();
        match &m.items[0] {
            Item::Conflict(c) => {
                assert_eq!(c.decision.as_deref(), Some("D"));
                assert_eq!(c.prefer, None);
                assert_eq!(c.reason.as_deref(), Some("see the decision file"));
            }
            other => panic!("wrong item: {other:?}"),
        }
        match &m.items[1] {
            Item::Decision(d) => {
                assert_eq!(d.name, "D");
                assert_eq!(d.path, "decisions/d.txt");
                assert_eq!(d.prefer, "A");
                assert_eq!(d.over, "B");
                assert_eq!(d.signer.as_deref(), Some("auditor"));
            }
            other => panic!("wrong item: {other:?}"),
        }
    }

    #[test]
    fn parses_build_format() {
        let src = r#"
            build raw1 = binary("a.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64, load: 0x400000);
            build pe1 = binary("a.exe", sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", arch: x86_64, format: pe);
        "#;
        let m = parse_model("t.dg", src).unwrap();
        let formats: Vec<String> = m
            .items
            .iter()
            .map(|i| match i {
                Item::Build(b) => b.format.clone(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(formats, vec!["raw".to_string(), "pe".to_string()]);
    }

    #[test]
    fn rejects_unknown_build_format() {
        let src = r#"build b = binary("x", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", format: elf);"#;
        assert!(parse_model("t.dg", src).is_err());
    }

    #[test]
    fn parses_table_evidence() {
        let src = r#"ev e := table(ds_ops, format: "csv", has_header: true);"#;
        let m = parse_model("t.dg", src).unwrap();
        match &m.items[0] {
            Item::Evidence(ev) => match &ev.kind {
                EvidenceKind::Table {
                    dataset,
                    format,
                    has_header,
                } => {
                    assert_eq!(dataset, "ds_ops");
                    assert_eq!(format, "csv");
                    assert!(*has_header);
                }
                other => panic!("expected table evidence, got {other:?}"),
            },
            other => panic!("expected evidence, got {other:?}"),
        }
    }

    #[test]
    fn conflict_rejects_prefer_and_decision() {
        let src = r#"conflict C : A vs B prefer A decision D;"#;
        let err = parse_model("t.dg", src).unwrap_err();
        assert!(err.contains("has both prefer and decision"), "{err}");
    }

    #[test]
    fn samples_evidence_rejects_unknown_delim() {
        let src = r#"
            build b1 = binary("g.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64);
            ev e := samples(ds, value: 0, delim: "psv");
        "#;
        let err = parse_model("t.dg", src).unwrap_err();
        assert!(err.contains("unknown delimiter"), "{err}");
    }

    #[test]
    fn unknown_evidence_kinds_become_extensions() {
        let src = r#"ev e := faketest(x, n: 3) |> unique;"#;
        let m = parse_model("t.dg", src).unwrap();
        match &m.items[0] {
            Item::Evidence(ev) => match &ev.kind {
                EvidenceKind::Extension { kind, args } => {
                    assert_eq!(kind, "faketest");
                    assert_eq!(args.positional_string(0).unwrap(), "x");
                    assert_eq!(args.u64("n"), Some(3));
                    assert!(ev.unique());
                }
                other => panic!("expected extension evidence, got {other:?}"),
            },
            other => panic!("expected evidence, got {other:?}"),
        }
    }
}

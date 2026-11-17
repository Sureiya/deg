//! Abstract syntax for DeG models.

use crate::lexer::Span;
use crate::strength::Strength;
pub use crate::value::Lit;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Model {
    pub path: String,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone)]
pub enum Item {
    Pragma(PragmaDecl),
    Build(BuildDecl),
    Capture(CaptureDecl),
    Dump(DumpDecl),
    Dataset(DatasetDecl),
    Clock(ClockDecl),
    Relate(RelateDecl),
    Struct(StructDecl),
    Packet(PacketDecl),
    Fn(FnDecl),
    Rng(RngDecl),
    Dist(DistDecl),
    Evidence(EvidenceDecl),
    Rule(RuleDecl),
    Proof(ProofDecl),
    Claim(ClaimDecl),
    Conflict(ConflictDecl),
    Obligation(ObligationDecl),
    Refute(RefuteDecl),
    Port(PortDecl),
}

impl Item {
    pub fn kind(&self) -> &'static str {
        match self {
            Item::Pragma(_) => "pragma",
            Item::Build(_) => "build",
            Item::Capture(_) => "capture",
            Item::Dump(_) => "dump",
            Item::Dataset(_) => "dataset",
            Item::Clock(_) => "clock",
            Item::Relate(_) => "relate",
            Item::Struct(_) => "struct",
            Item::Packet(_) => "packet",
            Item::Fn(_) => "fn",
            Item::Rng(_) => "rng",
            Item::Dist(_) => "dist",
            Item::Evidence(_) => "evidence",
            Item::Rule(_) => "rule",
            Item::Proof(_) => "proof",
            Item::Claim(_) => "claim",
            Item::Conflict(_) => "conflict",
            Item::Obligation(_) => "obligation",
            Item::Refute(_) => "refute",
            Item::Port(_) => "port",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PragmaDecl {
    pub key: String,
    pub value: Lit,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct BuildDecl {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub arch: String,
    pub load: u64,
    pub text: Option<(u64, u64)>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CaptureDecl {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub build: Option<String>,
    pub filter: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct DumpDecl {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub base: u64,
    pub build: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct DatasetDecl {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub build: Option<String>,
    pub from: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ClockDecl {
    pub name: String,
    pub kind: String,
    pub build: Option<String>,
    pub hz: Option<f64>,
    pub epoch: Option<String>,
    pub monotone: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct RelateDecl {
    pub a: String,
    pub b: String,
    pub within_us: u64,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ty {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Bool,
    Bytes,
}

impl Ty {
    pub fn width(self) -> u64 {
        match self {
            Ty::U8 | Ty::I8 | Ty::Bool => 1,
            Ty::U16 | Ty::I16 => 2,
            Ty::U32 | Ty::I32 | Ty::F32 => 4,
            Ty::U64 | Ty::I64 | Ty::F64 => 8,
            Ty::Bytes => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Ty::U8 => "u8",
            Ty::U16 => "u16",
            Ty::U32 => "u32",
            Ty::U64 => "u64",
            Ty::I8 => "i8",
            Ty::I16 => "i16",
            Ty::I32 => "i32",
            Ty::I64 => "i64",
            Ty::F32 => "f32",
            Ty::F64 => "f64",
            Ty::Bool => "bool",
            Ty::Bytes => "bytes",
        }
    }

    pub fn parse(s: &str) -> Option<Ty> {
        match s {
            "u8" => Some(Ty::U8),
            "u16" => Some(Ty::U16),
            "u32" => Some(Ty::U32),
            "u64" => Some(Ty::U64),
            "i8" => Some(Ty::I8),
            "i16" => Some(Ty::I16),
            "i32" => Some(Ty::I32),
            "i64" => Some(Ty::I64),
            "f32" => Some(Ty::F32),
            "f64" => Some(Ty::F64),
            "bool" => Some(Ty::Bool),
            "bytes" => Some(Ty::Bytes),
            _ => None,
        }
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub name: String,
    pub ty: FieldTy,
    pub offset: u64,
    pub constant: Option<i128>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum FieldTy {
    Scalar(Ty),
    Named(String),
}

impl FieldTy {
    pub fn display(&self) -> String {
        match self {
            FieldTy::Scalar(t) => t.to_string(),
            FieldTy::Named(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StructDecl {
    pub name: String,
    pub build: String,
    pub fields: Vec<FieldDecl>,
    pub size: u64,
    pub align: u64,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct PacketDecl {
    pub name: String,
    pub build: String,
    pub fields: Vec<FieldDecl>,
    pub size: u64,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FnDecl {
    pub name: String,
    pub build: String,
    pub addr: u64,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RngAlgo {
    Mt19937,
    XorShift32,
    XorShift128,
    Lcg { m: u64, a: u64, c: u64 },
    Other(String),
}

impl RngAlgo {
    pub fn as_str(&self) -> String {
        match self {
            RngAlgo::Mt19937 => "MT19937".into(),
            RngAlgo::XorShift32 => "XORSHIFT32".into(),
            RngAlgo::XorShift128 => "XORSHIFT128".into(),
            RngAlgo::Lcg { m, a, c } => format!("LCG(m:{m},a:{a},c:{c})"),
            RngAlgo::Other(s) => s.clone(),
        }
    }

    pub fn canonical(&self) -> String {
        match self {
            RngAlgo::Mt19937 => "MT19937".into(),
            RngAlgo::XorShift32 => "XORSHIFT32".into(),
            RngAlgo::XorShift128 => "XORSHIFT128".into(),
            RngAlgo::Lcg { .. } => "LCG".into(),
            RngAlgo::Other(s) => s.clone(),
        }
    }

    pub fn state_words(&self) -> Option<usize> {
        match self {
            RngAlgo::Mt19937 => Some(624),
            RngAlgo::XorShift32 => Some(1),
            RngAlgo::XorShift128 => Some(4),
            RngAlgo::Lcg { .. } => Some(1),
            RngAlgo::Other(_) => None,
        }
    }
}

impl fmt::Display for RngAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct RngDecl {
    pub name: String,
    pub build: String,
    pub addr: u64,
    pub algo: RngAlgo,
    pub seed: Option<String>,
    pub scope: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct DistDecl {
    pub name: String,
    pub build: String,
    pub rng: String,
    pub site: String,
    pub bins: u64,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Target {
    Addr(u64),
    Ref(String),
}

impl Target {
    pub fn display(&self) -> String {
        match self {
            Target::Addr(a) => format!("{a:#x}"),
            Target::Ref(r) => r.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceDecl {
    pub name: String,
    pub kind: EvidenceKind,
    pub modifiers: Vec<String>,
    pub span: Span,
}

impl EvidenceDecl {
    pub fn unique(&self) -> bool {
        self.modifiers.iter().any(|m| m == "unique")
    }
}

#[derive(Debug, Clone)]
pub enum EvidenceKind {
    Scan {
        build: String,
        section: String,
        pattern: String,
    },
    Bytes {
        artifact: String,
        at: u64,
        expect: String,
    },
    Decode {
        build: String,
        func: String,
        count: usize,
    },
    Constants {
        build: String,
        at: Target,
        window: u64,
        values: Vec<u32>,
        unique: bool,
    },
    Modulo {
        build: String,
        func: String,
        modulus: u64,
    },
    Recovery {
        rng: String,
        algo: Option<RngAlgo>,
        state: String,
        index: u64,
        observed: String,
        projection: String,
    },
    Rate {
        capture: String,
        opcode: u16,
        clock: Option<String>,
    },
    Sample {
        capture: String,
        opcode: u16,
        field: usize,
        width: usize,
        big_endian: bool,
    },
    External {
        path: String,
        kind: String,
        build: String,
    },
    Symbols {
        build: String,
        path: String,
    },
    Absence {
        path: String,
        build: String,
        scope: String,
        during: String,
    },
}

impl EvidenceKind {
    pub fn name(&self) -> &'static str {
        match self {
            EvidenceKind::Scan { .. } => "scan",
            EvidenceKind::Bytes { .. } => "bytes",
            EvidenceKind::Decode { .. } => "decode",
            EvidenceKind::Constants { .. } => "constants",
            EvidenceKind::Modulo { .. } => "modulo",
            EvidenceKind::Recovery { .. } => "recovery",
            EvidenceKind::Rate { .. } => "rate",
            EvidenceKind::Sample { .. } => "sample",
            EvidenceKind::External { .. } => "external",
            EvidenceKind::Symbols { .. } => "symbols",
            EvidenceKind::Absence { .. } => "absence",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Arg {
    pub name: Option<String>,
    pub value: ArgVal,
}

#[derive(Debug, Clone)]
pub enum ArgVal {
    Lit(Lit),
    Range(u64, u64),
}

impl ArgVal {
    pub fn as_lit(&self) -> Option<&Lit> {
        match self {
            ArgVal::Lit(l) => Some(l),
            ArgVal::Range(..) => None,
        }
    }

    pub fn display(&self) -> String {
        match self {
            ArgVal::Lit(l) => l.display(),
            ArgVal::Range(a, b) => format!("{a:#x}..{b:#x}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Args {
    pub positional: Vec<ArgVal>,
    pub named: BTreeMap<String, ArgVal>,
}

impl Args {
    pub fn empty() -> Args {
        Args {
            positional: Vec::new(),
            named: BTreeMap::new(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&ArgVal> {
        self.named.get(name)
    }

    pub fn lit(&self, name: &str) -> Option<&Lit> {
        self.get(name).and_then(ArgVal::as_lit)
    }

    pub fn string(&self, name: &str) -> Option<String> {
        self.lit(name).and_then(|l| match l {
            Lit::Str(s) | Lit::Sym(s) => Some(s.clone()),
            _ => None,
        })
    }

    pub fn u64(&self, name: &str) -> Option<u64> {
        self.lit(name).and_then(|l| match l {
            Lit::Int(n) => u64::try_from(*n).ok(),
            Lit::Duration(n) => Some(*n),
            _ => None,
        })
    }

    pub fn f64(&self, name: &str) -> Option<f64> {
        self.lit(name).and_then(|l| match l {
            Lit::Int(n) => Some(*n as f64),
            Lit::Float(v) => Some(*v),
            Lit::Duration(n) => Some(*n as f64),
            _ => None,
        })
    }

    pub fn bool(&self, name: &str) -> Option<bool> {
        self.lit(name).and_then(|l| match l {
            Lit::Bool(b) => Some(*b),
            Lit::Sym(s) if s == "true" => Some(true),
            Lit::Sym(s) if s == "false" => Some(false),
            _ => None,
        })
    }

    pub fn list(&self, name: &str) -> Option<&[Lit]> {
        self.lit(name).and_then(|l| match l {
            Lit::List(items) => Some(items.as_slice()),
            _ => None,
        })
    }

    pub fn positional_lit(&self, index: usize) -> Option<&Lit> {
        self.positional.get(index).and_then(ArgVal::as_lit)
    }

    pub fn positional_string(&self, index: usize) -> Option<String> {
        self.positional_lit(index).and_then(|l| match l {
            Lit::Str(s) | Lit::Sym(s) => Some(s.clone()),
            _ => None,
        })
    }

    pub fn positional_u64(&self, index: usize) -> Option<u64> {
        self.positional_lit(index).and_then(|l| match l {
            Lit::Int(n) => u64::try_from(*n).ok(),
            Lit::Duration(n) => Some(*n),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Var(String),
    Lit(Lit),
}

impl Term {
    pub fn display(&self) -> String {
        match self {
            Term::Var(v) => format!("?{v}"),
            Term::Lit(l) => l.display(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Atom {
    pub name: String,
    pub args: Vec<Term>,
    pub span: Span,
}

impl Atom {
    pub fn display(&self) -> String {
        let args: Vec<String> = self.args.iter().map(Term::display).collect();
        format!("{}({})", self.name, args.join(", "))
    }
}

#[derive(Debug, Clone)]
pub struct RuleDecl {
    pub name: String,
    pub head: Atom,
    pub body: Vec<Atom>,
    pub cap: Option<Strength>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ProofDecl {
    pub name: String,
    pub goal: Atom,
    pub build: String,
    pub evidence: Vec<String>,
    pub rules: Vec<String>,
    pub expect: Option<Strength>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum ClaimHead {
    Rel(Atom),
    Period {
        clock: String,
        stream: u16,
        period_us: u64,
        eps_us: u64,
    },
    Uniform {
        dist: String,
        bins: u64,
    },
}

impl ClaimHead {
    pub fn display(&self) -> String {
        match self {
            ClaimHead::Rel(a) => a.display(),
            ClaimHead::Period {
                clock,
                stream,
                period_us,
                eps_us,
            } => format!(
                "period({clock}, stream:{stream:#06x}) ~ {} +- {}",
                crate::value::format_duration(*period_us),
                crate::value::format_duration(*eps_us)
            ),
            ClaimHead::Uniform { dist, bins } => format!("uniform({dist}, bins:{bins})"),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ClaimHead::Rel(_) => "relational",
            ClaimHead::Period { .. } => "period",
            ClaimHead::Uniform { .. } => "uniform",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Requirement {
    CoverageAtLeast(u64),
    Alpha(f64),
    Power(f64),
    Delta(f64),
    ConfidenceAtLeast(f64),
    SamplesAtLeast(u64),
}

#[derive(Debug, Clone)]
pub enum ClaimBody {
    Direct {
        evidence: String,
        requires: Vec<Requirement>,
    },
    Derived {
        from: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ClaimDecl {
    pub name: String,
    pub head: ClaimHead,
    pub build: String,
    pub during: Option<String>,
    pub body: ClaimBody,
    pub provisional_until: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ConflictDecl {
    pub name: String,
    pub left: String,
    pub right: String,
    pub prefer: Option<String>,
    pub reason: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

impl Priority {
    pub fn parse(s: &str) -> Option<Priority> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Priority::Low),
            "medium" | "med" => Some(Priority::Medium),
            "high" => Some(Priority::High),
            "critical" => Some(Priority::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Priority::Low => "low",
            Priority::Medium => "medium",
            Priority::High => "high",
            Priority::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObligationDecl {
    pub name: String,
    pub atom: Atom,
    pub priority: Priority,
    pub blocks_seal: bool,
    pub resolved_by: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct RefuteDecl {
    pub name: String,
    pub goal: Atom,
    pub build: String,
    pub evidence: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum PortRule {
    Rebase {
        target: String,
        window: u64,
        min_similarity: f64,
    },
    Drop {
        target: String,
    },
    Revalidate {
        evidence: String,
        with: String,
    },
}

#[derive(Debug, Clone)]
pub struct PortDecl {
    pub from: String,
    pub to: String,
    pub rules: Vec<PortRule>,
    pub span: Span,
}

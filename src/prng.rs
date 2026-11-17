//! PRNG forward simulators used to re-check algebraic-recovery witnesses.
//!
//! The recovery *solver* is deliberately outside the kernel. It emits a witness
//! `(algorithm, state, index)`, and the kernel re-checks it by simulating the
//! claimed generator and comparing outputs. This module is the trusted,
//! decidable part of that split.

use crate::ast::RngAlgo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projection {
    Full32,
    High8,
    High16,
    Low8,
    Low16,
}

impl Projection {
    pub fn parse(s: &str) -> Option<Projection> {
        match s.to_ascii_lowercase().replace(['_', '-'], "").as_str() {
            "full" | "full32" | "u32" => Some(Projection::Full32),
            "high8" | "hi8" => Some(Projection::High8),
            "high16" | "hi16" => Some(Projection::High16),
            "low8" | "lo8" => Some(Projection::Low8),
            "low16" | "lo16" => Some(Projection::Low16),
            _ => None,
        }
    }

    pub fn apply(self, v: u32) -> u64 {
        match self {
            Projection::Full32 => v as u64,
            Projection::High8 => (v >> 24) as u64,
            Projection::High16 => (v >> 16) as u64,
            Projection::Low8 => (v & 0xff) as u64,
            Projection::Low16 => (v & 0xffff) as u64,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Projection::Full32 => "full32",
            Projection::High8 => "high8",
            Projection::High16 => "high16",
            Projection::Low8 => "low8",
            Projection::Low16 => "low16",
        }
    }
}

enum Sim {
    Lcg {
        m: u128,
        a: u128,
        c: u128,
        state: u128,
    },
    XorShift32(u32),
    XorShift128([u32; 4]),
    Mt(Box<Mt19937>),
}

impl Sim {
    fn next(&mut self) -> u32 {
        match self {
            Sim::Lcg { m, a, c, state } => {
                *state = (*a * *state + *c) % *m;
                (*state & 0xffff_ffff) as u32
            }
            Sim::XorShift32(x) => {
                let mut v = *x;
                v ^= v << 13;
                v ^= v >> 17;
                v ^= v << 5;
                *x = v;
                v
            }
            Sim::XorShift128(s) => {
                let [x, y, z, w] = s;
                let t = *x ^ (*x << 11);
                *x = *y;
                *y = *z;
                *z = *w;
                *w = *w ^ (*w >> 19) ^ t ^ (t >> 8);
                *w
            }
            Sim::Mt(mt) => mt.next(),
        }
    }
}

struct Mt19937 {
    state: [u32; 624],
    index: usize,
}

impl Mt19937 {
    fn next(&mut self) -> u32 {
        if self.index >= 624 {
            self.twist();
            self.index = 0;
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        y
    }

    fn twist(&mut self) {
        for i in 0..624 {
            let y = (self.state[i] & 0x8000_0000) | (self.state[(i + 1) % 624] & 0x7fff_ffff);
            self.state[i] =
                self.state[(i + 397) % 624] ^ (y >> 1) ^ if y & 1 != 0 { 0x9908_b0df } else { 0 };
        }
    }
}

/// Simulate `count` outputs. `state` words are individually validated against
/// the algorithm's width; `index` is the MT array cursor (624 means "twist on
/// the next output") and is metadata for the other algorithms.
pub fn simulate(
    algo: &RngAlgo,
    state: &[u64],
    index: u64,
    count: usize,
) -> Result<Vec<u32>, String> {
    let expected = algo
        .state_words()
        .ok_or_else(|| format!("recovery simulation is not implemented for {algo}"))?;
    if state.len() != expected {
        return Err(format!(
            "{algo} witness state needs {expected} words, got {}",
            state.len()
        ));
    }
    let as_u32 = |v: &u64, i: usize| -> Result<u32, String> {
        u32::try_from(*v).map_err(|_| format!("state word {i} ({v}) does not fit in 32 bits"))
    };

    let mut sim = match algo {
        RngAlgo::Mt19937 => {
            if index > 624 {
                return Err(format!("MT19937 index must be 0..=624, got {index}"));
            }
            let mut words = [0u32; 624];
            for (i, word) in words.iter_mut().enumerate() {
                *word = as_u32(&state[i], i)?;
            }
            Sim::Mt(Box::new(Mt19937 {
                state: words,
                index: index as usize,
            }))
        }
        RngAlgo::XorShift32 => {
            if index != 0 {
                return Err("xorshift32 witnesses use index 0".into());
            }
            Sim::XorShift32(as_u32(&state[0], 0)?)
        }
        RngAlgo::XorShift128 => {
            if index != 0 {
                return Err("xorshift128 witnesses use index 0".into());
            }
            let mut words = [0u32; 4];
            for (i, word) in words.iter_mut().enumerate() {
                *word = as_u32(&state[i], i)?;
            }
            Sim::XorShift128(words)
        }
        RngAlgo::Lcg { m, a, c } => {
            if index != 0 {
                return Err("LCG witnesses use index 0".into());
            }
            if *m == 0 {
                return Err("LCG modulus must be non-zero".into());
            }
            if state[0] >= *m {
                return Err(format!("LCG state {} is not below modulus {m}", state[0]));
            }
            Sim::Lcg {
                m: *m as u128,
                a: *a as u128,
                c: *c as u128,
                state: state[0] as u128,
            }
        }
        RngAlgo::Other(name) => {
            return Err(format!(
                "recovery simulation is not implemented for `{name}`"
            ))
        }
    };

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(sim.next());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcg_known_vector() {
        let algo = RngAlgo::Lcg {
            m: 1u64 << 32,
            a: 1_664_525,
            c: 1_013_904_223,
        };
        let out = simulate(&algo, &[1], 0, 6).unwrap();
        assert_eq!(
            out,
            vec![1015568748, 1586005467, 2165703038, 3027450565, 217083232, 1587069247]
        );
    }

    #[test]
    fn xorshift32_known_vector() {
        let out = simulate(&RngAlgo::XorShift32, &[1], 0, 6).unwrap();
        assert_eq!(
            out,
            vec![270369, 67634689, 2647435461, 307599695, 2398689233, 745495504]
        );
    }

    #[test]
    fn xorshift128_known_vector() {
        let state = [123456789, 362436069, 521288629, 88675123];
        let out = simulate(&RngAlgo::XorShift128, &state, 0, 6).unwrap();
        assert_eq!(
            out,
            vec![3701687786, 458299110, 2500872618, 3633119408, 516391518, 2377269574]
        );
    }

    #[test]
    fn mt19937_matches_reference_seed_5489() {
        // Python's random.Random(5489).getstate() state array, index 624.
        let raw = include_str!("../tests/data/mt_state_5489.txt");
        let state: Vec<u64> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let l = l.trim();
                if let Some(hex) = l.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).unwrap()
                } else {
                    l.parse().unwrap()
                }
            })
            .collect();
        assert_eq!(state.len(), 624);
        let out = simulate(&RngAlgo::Mt19937, &state, 624, 6).unwrap();
        assert_eq!(
            out,
            vec![3382763572, 956215839, 417760592, 166104981, 4181578304, 1596625880]
        );
    }

    #[test]
    fn projections_are_masks_not_hints() {
        assert_eq!(Projection::High8.apply(0x12345678), 0x12);
        assert_eq!(Projection::Low16.apply(0x12345678), 0x5678);
        assert_eq!(Projection::Full32.apply(0x12345678), 0x12345678);
    }
}

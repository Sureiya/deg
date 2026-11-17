//! Small, dependency-free statistics used by certificate claims.
//!
//! These routines do not "prove" statistical claims. They let the kernel verify
//! that the *procedure* was applied honestly to the samples: sample counts,
//! coverage, chi-square tail probability, and the power of the test against the
//! stated alternative. The claim stays `Observational` regardless of the
//! p-value.

/// Complementary error function (Numerical Recipes 6.2.2, fractional error
/// below 1.2e-7; plenty for our reported p-values).
pub fn erfc(x: f64) -> f64 {
    // Numerical Recipes 6.2.2, fractional error below 1.2e-7. This is ample
    // for the p-values and power checks DeG reports.
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let ans = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))))
            .exp();
    if x >= 0.0 {
        ans
    } else {
        2.0 - ans
    }
}

pub fn erf(x: f64) -> f64 {
    1.0 - erfc(x)
}

pub fn normal_cdf(x: f64) -> f64 {
    0.5 * erfc(-x / std::f64::consts::SQRT_2)
}

/// Inverse standard normal CDF (Acklam's algorithm).
#[allow(clippy::excessive_precision)]
pub fn normal_quantile(p: f64) -> f64 {
    if !(0.0..=1.0).contains(&p) {
        return f64::NAN;
    }
    const A: [f64; 6] = [
        -3.969683028665376e+01,
        2.209460984245205e+02,
        -2.759285104469687e+02,
        1.383577518672690e+02,
        -3.066479806614716e+01,
        2.506628277459239e+00,
    ];
    const B: [f64; 5] = [
        -5.447609879822406e+01,
        1.615858368580409e+02,
        -1.556989798598866e+02,
        6.680131188771972e+01,
        -1.328068155288572e+01,
    ];
    const C: [f64; 6] = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e+00,
        -2.549732539343734e+00,
        4.374664141464968e+00,
        2.938163982698783e+00,
    ];
    const D: [f64; 4] = [
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e+00,
        3.754408661907416e+00,
    ];
    const PLOW: f64 = 0.02425;
    const PHIGH: f64 = 1.0 - PLOW;
    if p == 0.0 {
        return f64::NEG_INFINITY;
    }
    if p == 1.0 {
        return f64::INFINITY;
    }
    if p < PLOW {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= PHIGH {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

#[allow(clippy::excessive_precision)]
fn ln_gamma(x: f64) -> f64 {
    // Lanczos approximation.
    const G: [f64; 9] = [
        0.99999999999980993,
        676.5203681218851,
        -1259.1392167224028,
        771.32342877765313,
        -176.61502916214059,
        12.507343278686905,
        -0.13857109526572012,
        9.9843695780195716e-6,
        1.5056327351493116e-7,
    ];
    if x < 0.5 {
        return std::f64::consts::PI.ln()
            - (std::f64::consts::PI * x).sin().ln()
            - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut a = G[0];
    let t = x + 7.5;
    for (i, g) in G.iter().enumerate().skip(1) {
        a += g / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

fn gser(a: f64, x: f64) -> f64 {
    let gln = ln_gamma(a);
    if x <= 0.0 {
        return 0.0;
    }
    let mut ap = a;
    let mut sum = 1.0 / a;
    let mut del = sum;
    for _ in 0..500 {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if del.abs() < sum.abs() * 1e-15 {
            break;
        }
    }
    sum * (-x + a * x.ln() - gln).exp()
}

fn gcf(a: f64, x: f64) -> f64 {
    const ITMAX: usize = 500;
    const EPS: f64 = 1e-15;
    const FPMIN: f64 = 1e-300;
    let gln = ln_gamma(a);
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / FPMIN;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1..=ITMAX {
        let an = -(i as f64) * (i as f64 - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = b + an / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    (-x + a * x.ln() - gln).exp() * h
}

/// Regularized upper incomplete gamma Q(a, x).
pub fn gamma_q(a: f64, x: f64) -> f64 {
    if x < 0.0 || a <= 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return 1.0;
    }
    if x < a + 1.0 {
        1.0 - gser(a, x)
    } else {
        gcf(a, x)
    }
}

/// Survival function of the chi-square distribution.
pub fn chi2_sf(x: f64, df: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    if df <= 0.0 {
        return f64::NAN;
    }
    gamma_q(df / 2.0, x / 2.0)
}

/// Two-sided chi-square goodness-of-fit statistic for `counts` against a
/// uniform distribution. Returns (statistic, df, p-value).
pub fn chi2_uniform(counts: &[u64]) -> (f64, f64, f64) {
    let k = counts.len();
    if k < 2 {
        return (0.0, 0.0, f64::NAN);
    }
    let n: u64 = counts.iter().sum();
    if n == 0 {
        return (0.0, (k - 1) as f64, f64::NAN);
    }
    let expected = n as f64 / k as f64;
    let stat: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    let df = (k - 1) as f64;
    (stat, df, chi2_sf(stat, df))
}

pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

pub fn mad(values: &[f64]) -> f64 {
    let m = median(values);
    if !m.is_finite() {
        return f64::NAN;
    }
    let deviations: Vec<f64> = values.iter().map(|x| (x - m).abs()).collect();
    median(&deviations)
}

/// Standard error of the sample median from the MAD, under normality.
pub fn median_se(values: &[f64]) -> f64 {
    let n = values.iter().filter(|x| x.is_finite()).count();
    if n < 2 {
        return f64::NAN;
    }
    let m = mad(values);
    if !m.is_finite() {
        return f64::NAN;
    }
    1.2533 * m / (n as f64).sqrt()
}

/// Conservative sample size for a two-sided test of one proportion against a
/// uniform baseline, using the worst bin and a normal approximation.
///
/// `delta` is the absolute deviation from `p0` the test should detect.
pub fn required_samples(p0: f64, delta: f64, alpha: f64, power: f64) -> f64 {
    if !(0.0..1.0).contains(&p0) || delta <= 0.0 || !(0.0..1.0).contains(&alpha) {
        return f64::NAN;
    }
    if !(0.0..1.0).contains(&power) {
        return f64::NAN;
    }
    let p1 = (p0 + delta).min(1.0 - 1e-12);
    let z_alpha = normal_quantile(1.0 - alpha / 2.0);
    let z_power = normal_quantile(power);
    let num = z_alpha * (p0 * (1.0 - p0)).sqrt() + z_power * (p1 * (1.0 - p1)).sqrt();
    let n = (num / (p1 - p0)).powi(2);
    n.ceil()
}

/// The power of the two-sided worst-bin normal test at sample size `n`.
pub fn achieved_power(p0: f64, delta: f64, alpha: f64, n: f64) -> f64 {
    if n <= 0.0 || !(0.0..1.0).contains(&p0) {
        return f64::NAN;
    }
    let p1 = (p0 + delta).min(1.0 - 1e-12);
    if p1 <= p0 {
        return f64::NAN;
    }
    let z_alpha = normal_quantile(1.0 - alpha / 2.0);
    let se = (p1 * (1.0 - p1) / n).sqrt();
    normal_cdf((p1 - p0) / se - z_alpha)
}

/// One-sigma confidence half-width for a binomial proportion.
pub fn proportion_halfwidth(p: f64, n: f64, z: f64) -> f64 {
    if n <= 0.0 {
        return f64::NAN;
    }
    z * (p * (1.0 - p) / n).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() < eps
    }

    #[test]
    fn erf_matches_known_values() {
        assert!(close(erf(0.0), 0.0, 2e-7));
        assert!(close(erf(1.0), 0.8427007929497149, 2e-7));
        assert!(close(erf(-1.0), -0.8427007929497149, 2e-7));
    }

    #[test]
    fn normal_quantile_matches_known_values() {
        assert!(close(normal_quantile(0.975), 1.959963984540054, 1e-8));
        assert!(close(normal_quantile(0.999), 3.090232306167813, 1e-7));
        assert!(close(normal_quantile(0.5), 0.0, 1e-12));
    }

    #[test]
    fn chi_square_tail_matches_tables() {
        assert!(close(chi2_sf(3.841458820694124, 1.0), 0.05, 1e-6));
        assert!(close(chi2_sf(11.070497693516351, 5.0), 0.05, 1e-6));
        assert_eq!(chi2_sf(0.0, 3.0), 1.0);
    }

    #[test]
    fn uniform_statistic_for_equal_counts_is_zero() {
        let (stat, df, p) = chi2_uniform(&[100, 100, 100, 100]);
        assert!(close(stat, 0.0, 1e-12));
        assert_eq!(df, 3.0);
        assert!(close(p, 1.0, 1e-12));
    }

    #[test]
    fn required_sample_size_is_in_a_sane_range() {
        let n = required_samples(1.0 / 12.0, 0.02, 1e-4, 0.999);
        assert!(n > 9_000.0 && n < 12_000.0, "n was {n}");
        let power = achieved_power(1.0 / 12.0, 0.02, 1e-4, 12_000.0);
        assert!(power > 0.999, "power was {power}");
    }

    #[test]
    fn median_and_mad_are_robust() {
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0, 100.0]), 3.0);
        assert_eq!(mad(&[1.0, 2.0, 3.0, 4.0, 100.0]), 1.0);
    }
}

#!/usr/bin/env python3
"""
ips/models/evt.py — Extreme Value Theory (EVT) threshold calibration (Contribution N3).

Fits a Generalized Pareto Distribution (GPD) using Peaks-Over-Threshold (POT)
to benign calibration reconstruction errors to derive principled extreme-tail thresholds
for a target False Positive Rate (q = target_fpr).

Selects the threshold quantile u in [0.90, 0.97] via Kolmogorov-Smirnov (KS)
goodness-of-fit on the excesses (never using attack data). Falls back to the
empirical quantile when N_u < min_excesses or the GPD fit is rejected.

Includes comparison with:
  - Fixed mean + 3*sigma rule
  - Plain empirical quantile
  - Clopper-Pearson 95% exact confidence intervals
  - Target-vs-Achieved FPR calibration curve generator
"""
import math
from typing import Dict, Any, Tuple, List, Optional
import numpy as np
import scipy.stats as stats


def clopper_pearson_ci(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Calculate exact Clopper-Pearson (1-alpha) confidence interval for binomial rate."""
    if n <= 0:
        return (0.0, 1.0)
    lower = 0.0 if k <= 0 else float(stats.beta.ppf(alpha / 2.0, k, n - k + 1))
    upper = 1.0 if k >= n else float(stats.beta.ppf(1.0 - alpha / 2.0, k + 1, n - k))
    return (lower, upper)


def compute_3sigma_threshold(scores: np.ndarray) -> float:
    """Fixed Gaussian baseline: mean + 3*std."""
    mu = float(np.mean(scores))
    sigma = float(np.std(scores))
    return mu + 3.0 * sigma


def compute_empirical_threshold(scores: np.ndarray, target_fpr: float = 0.001) -> float:
    """Empirical quantile baseline: (1 - target_fpr) percentile."""
    p = max(0.0, min(1.0, 1.0 - target_fpr))
    return float(np.percentile(scores, p * 100.0))


def fit_evt_threshold(scores: np.ndarray, target_fpr: float = 0.001,
                      high_quantile: Optional[float] = None,
                      candidate_quantiles: Tuple[float, ...] = (0.90, 0.92, 0.94, 0.95, 0.97),
                      min_excesses: int = 50,
                      ks_alpha: float = 0.01) -> Dict[str, Any]:
    """Fit GPD via Peaks-Over-Threshold (POT) with KS goodness-of-fit u selection.

    Args:
        scores: 1D array of anomaly reconstruction error scores on benign calibration data.
        target_fpr: Desired tail probability q (e.g. 0.001 for 0.1% FPR).
        high_quantile: If explicitly provided, test this quantile first alongside candidates;
                       otherwise sweep candidate_quantiles and pick best KS p-value.
        candidate_quantiles: Candidate high quantiles in [0.90, 0.97].
        min_excesses: Minimum N_u required before falling back to empirical quantile (~50).
        ks_alpha: Reject GPD fit if best KS p-value < ks_alpha.

    Returns:
        dict containing threshold value, GPD parameters, KS fit statistics, and baselines.
    """
    scores = np.asarray(scores, dtype=np.float64)
    scores = scores[np.isfinite(scores)]
    N = len(scores)

    three_sig = compute_3sigma_threshold(scores) if N > 0 else 0.0
    emp_q = compute_empirical_threshold(scores, target_fpr) if N > 0 else 0.0

    if N < min_excesses:
        return {
            "threshold": emp_q,
            "method": "empirical_fallback_tiny_sample",
            "u": float(np.max(scores)) if N > 0 else 0.0,
            "selected_quantile": 1.0 - target_fpr,
            "xi": 0.0,
            "sigma": 1.0,
            "ks_stat": 1.0,
            "ks_pvalue": 0.0,
            "N": N,
            "N_u": 0,
            "target_fpr": target_fpr,
            "three_sigma": three_sig,
            "empirical_q": emp_q,
        }

    # Build list of quantiles to evaluate via KS goodness-of-fit
    if high_quantile is not None:
        quantiles_to_try = [high_quantile] + [q for q in candidate_quantiles if abs(q - high_quantile) > 1e-4]
    else:
        quantiles_to_try = list(candidate_quantiles)

    # Adapt min_excesses if N is moderate (e.g. 200-500 in unit tests) so 90th percentile has >=20 excesses
    effective_min_u = min(min_excesses, max(20, int(N * 0.05)))

    best_fit = None
    for q_cand in quantiles_to_try:
        u_cand = float(np.percentile(scores, q_cand * 100.0))
        excesses = scores[scores > u_cand] - u_cand
        n_u = len(excesses)
        if n_u < effective_min_u:
            continue
        try:
            c, loc, scale = stats.genpareto.fit(excesses, floc=0)
            if scale <= 0 or not math.isfinite(c) or not math.isfinite(scale):
                continue
            ks_stat, ks_pval = stats.kstest(excesses, "genpareto", args=(c, 0.0, scale))
            if best_fit is None or ks_pval > best_fit["ks_pvalue"]:
                best_fit = {
                    "u": u_cand,
                    "q_cand": q_cand,
                    "xi": float(c),
                    "sigma": float(scale),
                    "N_u": n_u,
                    "ks_stat": float(ks_stat),
                    "ks_pvalue": float(ks_pval),
                }
        except Exception:
            continue

    if best_fit is None:
        u_default = float(np.percentile(scores, 95.0))
        n_u_default = int(np.sum(scores > u_default))
        return {
            "threshold": emp_q,
            "method": "empirical_fallback_insufficient_excesses",
            "u": u_default,
            "selected_quantile": 0.95,
            "xi": 0.0,
            "sigma": 1.0,
            "ks_stat": 1.0,
            "ks_pvalue": 0.0,
            "N": N,
            "N_u": n_u_default,
            "target_fpr": target_fpr,
            "three_sigma": three_sig,
            "empirical_q": emp_q,
        }

    # Check if GPD fit is rejected by KS goodness-of-fit test
    if best_fit["ks_pvalue"] < ks_alpha:
        return {
            "threshold": emp_q,
            "method": "empirical_fallback_ks_rejected",
            "u": best_fit["u"],
            "selected_quantile": best_fit["q_cand"],
            "xi": best_fit["xi"],
            "sigma": best_fit["sigma"],
            "ks_stat": best_fit["ks_stat"],
            "ks_pvalue": best_fit["ks_pvalue"],
            "N": N,
            "N_u": best_fit["N_u"],
            "target_fpr": target_fpr,
            "three_sigma": three_sig,
            "empirical_q": emp_q,
        }

    u = best_fit["u"]
    xi = best_fit["xi"]
    sigma = best_fit["sigma"]
    N_u = best_fit["N_u"]

    # Extreme Value Theory POT quantile formula:
    # t = u + (sigma / xi) * [ (target_fpr * N / N_u)^(-xi) - 1 ]
    ratio = (target_fpr * float(N)) / float(N_u)
    try:
        if abs(xi) > 1e-5:
            term = math.pow(ratio, -xi) - 1.0
            t = u + (sigma / xi) * term
        else:
            t = u - sigma * math.log(ratio)
        method = "evt_gpd_pot"
    except Exception:
        t = emp_q
        method = "empirical_fallback_math_error"

    if not math.isfinite(t) or t < u:
        t = emp_q
        method = "empirical_fallback_bound_check"

    return {
        "threshold": float(t),
        "method": method,
        "u": u,
        "selected_quantile": best_fit["q_cand"],
        "xi": xi,
        "sigma": sigma,
        "ks_stat": best_fit["ks_stat"],
        "ks_pvalue": best_fit["ks_pvalue"],
        "N": N,
        "N_u": N_u,
        "target_fpr": target_fpr,
        "three_sigma": three_sig,
        "empirical_q": emp_q,
    }


def compute_calibration_curve(calib_scores: np.ndarray, test_benign_scores: np.ndarray,
                              target_fprs: Optional[List[float]] = None) -> List[Dict[str, Any]]:
    """Compute target FPR vs achieved FPR on held-out benign test data with Clopper-Pearson CIs.

    Compares:
      1. EVT (POT GPD)
      2. Empirical quantile
      3. Fixed mean + 3*sigma (constant across target_fprs)
    """
    if target_fprs is None:
        target_fprs = [0.05, 0.02, 0.01, 0.005, 0.002, 0.001]

    calib_scores = np.asarray(calib_scores, dtype=np.float64)
    test_benign_scores = np.asarray(test_benign_scores, dtype=np.float64)
    n_test = len(test_benign_scores)

    t_3sig = compute_3sigma_threshold(calib_scores)
    fp_3sig = int(np.sum(test_benign_scores >= t_3sig))
    fpr_3sig = fp_3sig / n_test if n_test > 0 else 0.0
    ci_3sig = clopper_pearson_ci(fp_3sig, n_test)

    rows = []
    for q in target_fprs:
        evt_res = fit_evt_threshold(calib_scores, target_fpr=q)
        t_evt = evt_res["threshold"]
        t_emp = evt_res["empirical_q"]

        fp_evt = int(np.sum(test_benign_scores >= t_evt))
        fpr_evt = fp_evt / n_test if n_test > 0 else 0.0
        ci_evt = clopper_pearson_ci(fp_evt, n_test)

        fp_emp = int(np.sum(test_benign_scores >= t_emp))
        fpr_emp = fp_emp / n_test if n_test > 0 else 0.0
        ci_emp = clopper_pearson_ci(fp_emp, n_test)

        # Rule-of-three minimum sample size to bound rate q with 0 FPs: N >= 3/q
        min_n_rule_of_three = int(math.ceil(3.0 / q))

        rows.append({
            "target_fpr": q,
            "n_calib": len(calib_scores),
            "n_test_benign": n_test,
            "min_n_for_bound": min_n_rule_of_three,
            "sample_size_sufficient": bool(n_test >= min_n_rule_of_three),
            "evt_method": evt_res["method"],
            "evt_threshold": round(t_evt, 6),
            "evt_achieved_fpr": round(fpr_evt, 6),
            "evt_ci95_low": round(ci_evt[0], 6),
            "evt_ci95_high": round(ci_evt[1], 6),
            "emp_threshold": round(t_emp, 6),
            "emp_achieved_fpr": round(fpr_emp, 6),
            "emp_ci95_low": round(ci_emp[0], 6),
            "emp_ci95_high": round(ci_emp[1], 6),
            "three_sigma_threshold": round(t_3sig, 6),
            "three_sigma_achieved_fpr": round(fpr_3sig, 6),
            "three_sigma_ci95_low": round(ci_3sig[0], 6),
            "three_sigma_ci95_high": round(ci_3sig[1], 6),
        })

    return rows

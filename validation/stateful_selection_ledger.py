"""
OmniCompiler Stateful Selection Ledger & Anti-Goodhart Evaluation Engine (stateful_selection_ledger.py).
Enforces non-replayable evaluation tickets, Holm-Bonferroni family-wise error rate (FWER) control,
cluster-aware multi-rollout stability, and multi-objective Pareto promotion (Q, F, C, L, K, P).
Conforms to Master Prompt Protocol Alpha-C13.
"""

import hashlib
import json
import math
import os
import time
from typing import Dict, List, Any, Optional, Tuple


class EvaluationTicket:
    """Non-replayable single-use evaluation ticket."""

    def __init__(
        self,
        ticket_id: str,
        baseline_commit: str,
        candidate_hash: str,
        eval_plan_hash: str,
        allocated_at: float,
        is_consumed: bool = False,
        outcome: Optional[Dict[str, Any]] = None,
    ):
        self.ticket_id = ticket_id
        self.baseline_commit = baseline_commit
        self.candidate_hash = candidate_hash
        self.eval_plan_hash = eval_plan_hash
        self.allocated_at = allocated_at
        self.is_consumed = is_consumed
        self.outcome = outcome

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "baseline_commit": self.baseline_commit,
            "candidate_hash": self.candidate_hash,
            "eval_plan_hash": self.eval_plan_hash,
            "allocated_at": self.allocated_at,
            "is_consumed": self.is_consumed,
            "outcome": self.outcome,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvaluationTicket":
        return cls(
            ticket_id=d["ticket_id"],
            baseline_commit=d["baseline_commit"],
            candidate_hash=d["candidate_hash"],
            eval_plan_hash=d["eval_plan_hash"],
            allocated_at=d["allocated_at"],
            is_consumed=d.get("is_consumed", False),
            outcome=d.get("outcome"),
        )


class StatefulSelectionLedger:
    """
    Stateful ledger allocating single-use evaluation tickets and preventing
    data snooping, winner's curse, and benchmark overfitting.
    """

    def __init__(self, ledger_path: str):
        self.ledger_path = ledger_path
        self.tickets: Dict[str, EvaluationTicket] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("tickets", []):
                        t = EvaluationTicket.from_dict(item)
                        self.tickets[t.ticket_id] = t
            except Exception:
                pass

    def _save(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.ledger_path)), exist_ok=True)
        temp_path = self.ledger_path + ".tmp"
        payload = {
            "version": "1.0",
            "protocol": "ALPHA-C13-STATEFUL-SELECTION",
            "updated_at": time.time(),
            "tickets": [t.to_dict() for t in self.tickets.values()],
        }
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(temp_path, self.ledger_path)

    def allocate_ticket(self, baseline_commit: str, candidate_hash: str, eval_plan_hash: str) -> EvaluationTicket:
        """Allocates a unique non-replayable evaluation ticket bound to the evaluation plan."""
        nonce_src = f"{baseline_commit}:{candidate_hash}:{eval_plan_hash}:{time.perf_counter()}:{os.urandom(8).hex()}"
        ticket_id = "TCK-" + hashlib.sha256(nonce_src.encode("utf-8")).hexdigest()[:16]

        ticket = EvaluationTicket(
            ticket_id=ticket_id,
            baseline_commit=baseline_commit,
            candidate_hash=candidate_hash,
            eval_plan_hash=eval_plan_hash,
            allocated_at=time.time(),
            is_consumed=False,
            outcome=None,
        )
        self.tickets[ticket_id] = ticket
        self._save()
        return ticket

    def consume_ticket(self, ticket_id: str, outcome_data: Dict[str, Any]) -> EvaluationTicket:
        """Consumes a ticket with evaluation outcome. A ticket can only be consumed once."""
        if ticket_id not in self.tickets:
            raise KeyError(f"Evaluation ticket '{ticket_id}' not found in ledger")
        ticket = self.tickets[ticket_id]
        if ticket.is_consumed:
            raise ValueError(f"CRITICAL VIOLATION: Ticket '{ticket_id}' was already consumed; replay attack prevented.")

        ticket.is_consumed = True
        ticket.outcome = outcome_data
        self._save()
        return ticket


class AntiGoodhartPromoter:
    """
    Evaluates candidate families using Holm-Bonferroni FWER control and
    multi-objective Pareto analysis (Q, F, C, L, K, P).
    """

    def __init__(self, family_alpha: float = 0.05, epsilon_q: float = 0.02, min_quality_gain: float = 0.05):
        self.family_alpha = family_alpha
        self.epsilon_q = epsilon_q
        self.min_quality_gain = min_quality_gain

    def holm_bonferroni_correction(self, raw_p_values: List[float]) -> List[Tuple[float, float, bool]]:
        """
        Applies the step-down Holm-Bonferroni procedure to control Family-Wise Error Rate:
        alpha_i = alpha / (m - i + 1)
        Returns list of (p_value, adjusted_threshold, is_significant).
        """
        m = len(raw_p_values)
        if m == 0:
            return []

        # Pair with original indices
        indexed = sorted(enumerate(raw_p_values), key=lambda x: x[1])
        results: List[Optional[Tuple[float, float, bool]]] = [None] * m

        stop_rejecting = False
        for i, (orig_idx, p_val) in enumerate(indexed):
            threshold = self.family_alpha / float(m - i)
            if not stop_rejecting and p_val <= threshold:
                results[orig_idx] = (p_val, threshold, True)
            else:
                stop_rejecting = True
                results[orig_idx] = (p_val, threshold, False)

        return [r for r in results if r is not None]

    def evaluate_rollouts(
        self,
        candidate_measurements: List[float],
        baseline_measurements: List[float],
    ) -> Dict[str, Any]:
        """
        Evaluates repeated rollouts across seeds, computing empirical mean, standard error,
        Student's t-test statistic, and non-inferiority margin.
        """
        n_c = len(candidate_measurements)
        n_b = len(baseline_measurements)
        if n_c < 2 or n_b < 2:
            raise ValueError("Rollout evaluation requires at least 2 independent observations per group")

        mean_c = sum(candidate_measurements) / n_c
        mean_b = sum(baseline_measurements) / n_b

        var_c = sum((x - mean_c) ** 2 for x in candidate_measurements) / (n_c - 1)
        var_b = sum((x - mean_b) ** 2 for x in baseline_measurements) / (n_b - 1)

        se_diff = math.sqrt((var_c / n_c) + (var_b / n_b))
        diff = mean_c - mean_b

        t_stat = diff / max(1e-12, se_diff)
        # Approximate two-tailed p-value via normal CDF approximation
        z = abs(t_stat)
        p_val = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(z / math.sqrt(2.0))))

        gain_pct = (diff / max(1e-9, mean_b)) * 100.0
        meets_effect = diff >= self.min_quality_gain

        return {
            "candidate_mean": mean_c,
            "baseline_mean": mean_b,
            "diff": diff,
            "gain_pct": gain_pct,
            "se_diff": se_diff,
            "t_stat": t_stat,
            "p_value": p_val,
            "meets_effect_size": meets_effect,
            "is_significant": p_val < self.family_alpha,
        }

    def check_pareto_dominance(
        self,
        candidate_vector: Dict[str, float],
        baseline_vector: Dict[str, float],
    ) -> Tuple[bool, str]:
        """
        Evaluates Pareto dominance across:
        - Q: Quality (higher is better)
        - F: Critical Failures (must be exactly 0)
        - C: Cost / Time (lower is better)
        - L: Latency (lower is better)
        - K: Handoffs / Context hops (lower is better)
        - P: Prompt / Code bloat (lower is better)
        """
        if candidate_vector.get("F", 0) > 0:
            return False, "FAIL: Candidate has critical failures (F > 0)"

        q_cand = candidate_vector.get("Q", 0.0)
        q_base = baseline_vector.get("Q", 0.0)
        if q_cand < (q_base - self.epsilon_q):
            return False, f"FAIL: Candidate quality Q ({q_cand:.3f}) inferior to baseline ({q_base:.3f})"

        # Check resource regression limits (max 20% regression allowed if Q increases significantly)
        strictly_better = False
        if q_cand > q_base + self.min_quality_gain:
            strictly_better = True

        for resource_key in ("C", "L", "K", "P"):
            c_val = candidate_vector.get(resource_key, 1.0)
            b_val = baseline_vector.get(resource_key, 1.0)
            if c_val < b_val:
                strictly_better = True
            elif c_val > b_val * 1.25:
                return False, f"FAIL: Candidate regressed resource '{resource_key}' by >25% ({c_val} vs {b_val})"

        if strictly_better:
            return True, "PROMOTED: Candidate Pareto-dominates baseline with acceptable trade-offs"
        return False, "NEUTRAL: Candidate shows no material improvement over baseline"

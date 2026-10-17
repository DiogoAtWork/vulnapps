"""Scoring unit tests — the pure metric, with no DB in the way.

The worked example from ``tasks/scoring-redesign.md`` is reproduced exactly:
two configurations that are indistinguishable on raw counts (16/30 vs 17/30)
but more than 2x apart weighted (94/382 vs 227/382). If a change to the weight
scale or the credit rules ever breaks that separation, these fail.
"""

from app import scoring
from app.scoring import compute_metrics
import pytest


def test_weighted_f05_penalizes_clusters_and_pending_without_trusting_severity():
    reviewed = finding(2, fp=1, fp_group="duplicate", severity="critical")
    reviewed["fp_impact_weight"] = 3
    duplicate = finding(3, fp=1, fp_group="DUPLICATE", severity="info")
    duplicate["fp_impact_weight"] = 9
    findings = [finding(1, matched=1), reviewed, duplicate]
    metrics = compute_metrics(findings, [vuln(1, 27), vuln(2, 9)])
    assert metrics["weighted_fp_penalty"] == 9
    assert metrics["weighted_precision"] == pytest.approx(27 / 36)
    assert metrics["weighted_f05"] == pytest.approx(33.75 / 45)
    assert metrics["weighted_score_provisional"] is False

    findings.append(finding(4, severity="info"))
    metrics = compute_metrics(findings, [vuln(1, 27), vuln(2, 9)])
    assert metrics["weighted_pending_penalty"] == 27
    assert metrics["weighted_f05"] == pytest.approx(33.75 / 72)
    assert metrics["weighted_f05_upper"] == pytest.approx(33.75 / 45)
    assert metrics["weighted_score_provisional"] is True

    duplicate.pop("fp_impact_weight")
    metrics = compute_metrics(findings, [vuln(1, 27), vuln(2, 9)])
    assert metrics["weighted_fp_penalty"] == 27
    assert metrics["weighted_fp_unreviewed"] == 1
    assert metrics["weighted_f05"] == pytest.approx(33.75 / 90)


def test_weighted_f05_deduplicates_credit_and_handles_chain_only_and_empty_scans():
    chain = {"id": 10, "impact_weight": 27, "members": [1]}
    findings = [finding(1, matched=1, matched_chain=10), finding(2, matched=1, matched_chain=10)]
    metrics = compute_metrics(findings, [vuln(1, 9)], [chain])
    assert metrics["weighted_found"] == metrics["weighted_total"] == 36
    assert metrics["weighted_f05"] == 1
    assert compute_metrics([finding(1, matched_chain=10)], [], [chain])["weighted_f05"] == 1
    assert compute_metrics([], [vuln(1, 9)])["weighted_f05"] == 0
    assert compute_metrics([], [vuln(1, 9)])["weighted_precision"] is None
    assert compute_metrics([], [])["weighted_f05"] is None


# ---------------------------------------------------------------------------
# Fixtures — plain dicts, since compute_metrics is row-agnostic
# ---------------------------------------------------------------------------

def vuln(vid, weight, tier="commodity", **kw):
    row = {
        "id": vid,
        "impact_weight": weight,
        "difficulty_tier": tier,
        "severity": scoring.WEIGHT_CLASSES.get(weight, "medium"),
        "existed_since_revision": 1,
        "invalidated_at_revision": None,
    }
    row.update(kw)
    return row


def finding(fid, matched=None, fp=0, ignored=0, fp_group=None, severity=None,
            matched_chain=None, matched_vulns=None, matched_chains=None):
    """A ``scan_findings`` row as ``compute_metrics`` sees it.

    Since migration 040 a finding carries LISTS of matches rather than one id,
    because a single finding can demonstrate several things at once.
    ``matched=``/``matched_chain=`` stay as the single-target shorthand most
    tests want; ``matched_vulns=``/``matched_chains=`` set the full lists.
    """
    vuln_ids = (
        list(matched_vulns) if matched_vulns is not None
        else ([matched] if matched is not None else [])
    )
    chain_ids = (
        list(matched_chains) if matched_chains is not None
        else ([matched_chain] if matched_chain is not None else [])
    )
    return {
        "id": fid,
        "matched_vuln_ids": vuln_ids,
        "matched_chain_ids": chain_ids,
        "is_false_positive": fp,
        "is_ignored": ignored,
        "fp_group": fp_group,
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# The worked example: 30 vulns worth 382 points
# ---------------------------------------------------------------------------
# 12 commodity (4x1 + 6x3 + 2x9 = 40) + 14 business logic + 4 chained.
# Business logic: 8 high + 6 critical = 8*9 + 6*27 = 234.
# Chained: 4 x 27 = 108.  Total = 40 + 234 + 108 = 382.

def _corpus():
    vulns = []
    vid = 0
    for weight in [1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 9, 9]:
        vid += 1
        vulns.append(vuln(vid, weight, "commodity"))
    for weight in [9] * 8 + [27] * 6:
        vid += 1
        vulns.append(vuln(vid, weight, "business_logic"))
    for _ in range(4):
        vid += 1
        vulns.append(vuln(vid, 27, "chained"))
    return vulns


def _findings_for(vulns, ids):
    return [finding(1000 + i, matched=v) for i, v in enumerate(ids)]


def test_corpus_totals_382_over_30_items():
    vulns = _corpus()
    assert len(vulns) == 30
    assert sum(scoring.weight_of(v) for v in vulns) == 382


def test_config_a_scores_94_of_382():
    """All 12 commodity + 4 business logic (3 high, 1 critical) = 16/30 raw."""
    vulns = _corpus()
    commodity = [v["id"] for v in vulns if v["difficulty_tier"] == "commodity"]
    business = [v for v in vulns if v["difficulty_tier"] == "business_logic"]
    highs = [v["id"] for v in business if v["impact_weight"] == 9][:3]
    crits = [v["id"] for v in business if v["impact_weight"] == 27][:1]
    found = commodity + highs + crits

    m = compute_metrics(_findings_for(vulns, found), vulns)

    assert m["tp"] == 16
    assert m["fn"] == 14
    assert m["weighted_found"] == 94.0
    assert m["weighted_total"] == 382.0
    # Raw counts say 53%, the weighted metric says 25% — that gap is the point.
    assert round(m["tp"] / 30, 4) == 0.5333
    assert round(m["weighted_rate"], 4) == 0.2461


def test_config_b_scores_227_of_382():
    """6 commodity + 9 business logic (5 high, 4 critical) + 2 chained = 17/30 raw."""
    vulns = _corpus()
    # 6 commodity worth 20: 1+1+3+3+3+9
    commodity = [v for v in vulns if v["difficulty_tier"] == "commodity"]
    picked = (
        [v["id"] for v in commodity if v["impact_weight"] == 1][:2]
        + [v["id"] for v in commodity if v["impact_weight"] == 3][:3]
        + [v["id"] for v in commodity if v["impact_weight"] == 9][:1]
    )
    business = [v for v in vulns if v["difficulty_tier"] == "business_logic"]
    picked += [v["id"] for v in business if v["impact_weight"] == 9][:5]
    picked += [v["id"] for v in business if v["impact_weight"] == 27][:4]
    picked += [v["id"] for v in vulns if v["difficulty_tier"] == "chained"][:2]

    m = compute_metrics(_findings_for(vulns, picked), vulns)

    assert m["tp"] == 17
    assert m["weighted_found"] == 227.0
    assert m["weighted_total"] == 382.0
    assert round(m["weighted_rate"], 4) == 0.5942
    # Indistinguishable on counts (17/30 = 57% vs 16/30 = 53%), 2.4x apart weighted.
    assert m["weighted_rate"] / 0.2461 > 2.4


def test_tier_matrix_shape():
    vulns = _corpus()
    commodity = [v["id"] for v in vulns if v["difficulty_tier"] == "commodity"]
    business = [v for v in vulns if v["difficulty_tier"] == "business_logic"]
    found = commodity + [v["id"] for v in business][:4]

    tiers = compute_metrics(_findings_for(vulns, found), vulns)["tiers"]

    by_severity = tiers["commodity"].pop("found_by_severity")
    assert tiers["commodity"] == {
        "count": 12, "found": 12,
        "weighted_total": 40.0, "weighted_found": 40.0,
        "rate": 1.0, "weighted_rate": 1.0,
    }
    # The per-tier severity split sums to that tier's `found`, by catalog severity.
    expected = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for v in vulns:
        if v["difficulty_tier"] == "commodity":
            # Labels outside the scale (this corpus uses "informational") fold into info.
            sev = v["severity"] if v["severity"] in expected else "info"
            expected[sev] += 1
    assert by_severity == expected
    assert sum(tiers["business_logic"]["found_by_severity"].values()) == 4
    assert tiers["business_logic"]["count"] == 14
    assert tiers["business_logic"]["found"] == 4
    assert round(tiers["business_logic"]["rate"], 2) == 0.29
    assert tiers["chained"]["found"] == 0
    assert tiers["chained"]["rate"] == 0.0


def test_matched_vuln_scores_full_credit():
    """A matched vuln always earns its full weight — there is no partial
    credit (no milestone tracking)."""
    v = vuln(1, 27)
    m = compute_metrics([finding(10, matched=1)], [v])
    assert m["credit_by_vuln"][1] == 1.0
    assert m["weighted_found"] == 27.0
    assert m["tp"] == 1


# ---------------------------------------------------------------------------
# False-positive clustering
# ---------------------------------------------------------------------------

def test_fp_clustering_counts_groups_not_findings():
    v = vuln(1, 3)
    findings = [
        finding(10, matched=1),
        finding(11, fp=1, fp_group="missing-headers"),
        finding(12, fp=1, fp_group="missing-headers"),
        finding(13, fp=1, fp_group="MISSING-HEADERS"),   # case-insensitive
        finding(14, fp=1),                               # ungrouped: counts as one
    ]
    m = compute_metrics(findings, [v])
    assert m["fp"] == 4          # raw, retained for continuity
    assert m["fp_groups"] == 2   # one cluster + one ungrouped
    # Precision uses the clustered count: 1/(1+2), not 1/(1+4).
    assert round(m["precision_upper"], 4) == 0.3333


def test_ungrouped_fps_still_count_individually():
    v = vuln(1, 3)
    findings = [finding(10, matched=1)] + [finding(20 + i, fp=1) for i in range(3)]
    m = compute_metrics(findings, [v])
    assert m["fp_groups"] == 3


# ---------------------------------------------------------------------------
# Precision bounds
# ---------------------------------------------------------------------------

def test_precision_bounds_expose_unadjudicated_findings():
    """5 TP, 0 FP, 50 pending used to report precision = 1.0."""
    vulns = [vuln(i, 3) for i in range(1, 6)]
    findings = [finding(100 + i, matched=i) for i in range(1, 6)]
    findings += [finding(200 + i) for i in range(50)]

    m = compute_metrics(findings, vulns)

    assert m["pending"] == 50
    assert m["adjudication_complete"] is False
    assert m["precision_upper"] == 1.0                    # every pending is a TP
    assert round(m["precision_lower"], 4) == 0.0909       # every pending is an FP
    assert m["precision_lower"] < m["precision_upper"]


def test_bounds_converge_when_fully_adjudicated():
    vulns = [vuln(1, 3), vuln(2, 3)]
    findings = [finding(10, matched=1), finding(11, fp=1)]
    m = compute_metrics(findings, vulns)
    assert m["adjudication_complete"] is True
    assert m["precision_lower"] == m["precision_upper"] == 0.5


def test_ignored_findings_stay_neutral():
    vulns = [vuln(1, 3)]
    findings = [finding(10, matched=1), finding(11, ignored=1)]
    m = compute_metrics(findings, vulns)
    assert m["ignored"] == 1
    assert m["pending"] == 0
    assert m["precision_upper"] == 1.0
    assert m["adjudication_complete"] is True


# ---------------------------------------------------------------------------
# Revision scope
# ---------------------------------------------------------------------------

def test_scope_rule():
    v = vuln(1, 3, existed_since_revision=3, invalidated_at_revision=5)
    assert scoring.in_scope(v, 2) is False   # not yet introduced
    assert scoring.in_scope(v, 3) is True
    assert scoring.in_scope(v, 4) is True
    assert scoring.in_scope(v, 5) is False   # invalidated at 5
    assert scoring.in_scope(vuln(2, 3), 9) is True


def test_match_to_out_of_scope_vuln_is_neither_tp_nor_fp():
    in_scope_vuln = vuln(1, 3)
    findings = [finding(10, matched=1), finding(11, matched=99)]  # 99 not in scope
    m = compute_metrics(findings, [in_scope_vuln])
    assert m["tp"] == 1
    assert m["fp"] == 0
    assert m["out_of_scope_matches"] == 1


# ---------------------------------------------------------------------------
# Chains
# ---------------------------------------------------------------------------

def test_chain_adds_its_own_weight_to_the_total():
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}
    m = compute_metrics([], vulns, [chain])
    # 9 + 9 + 27: the chain is its own ground-truth entity.
    assert m["weighted_total"] == 45.0
    assert m["tiers"]["chained"]["count"] == 1


def test_chain_credit_requires_all_members_matched():
    """Matching only some members earns nothing, matched-but-unconfirmed
    (no partial credit; there is no chain-level milestone tracking)."""
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}

    one_step = compute_metrics([finding(10, matched=1)], vulns, [chain], confirmed_chain_ids=[7])
    assert one_step["credit_by_chain"][7] == 0.0
    assert one_step["weighted_found"] == 9.0        # member 1 only

    both = compute_metrics(
        [finding(10, matched=1), finding(11, matched=2)], vulns, [chain], confirmed_chain_ids=[7]
    )
    assert both["credit_by_chain"][7] == 1.0
    assert both["weighted_found"] == 45.0           # 9 + 9 + 27
    assert both["weighted_total"] == 45.0
    # Asymmetric with vulns on purpose: for a vuln the match IS the evidence.
    assert both["credit_by_vuln"][1] == 1.0


def test_chain_credit_requires_explicit_confirmation_even_when_all_members_matched():
    """Matching every member is necessary but NOT sufficient — confirmed on
    real scan data where two findings independently matched a chain's two
    members while one finding's own text explicitly denied any connection
    between them, and it still scored full chain credit under the old rule
    (credit inferred from matching alone). A reviewer must explicitly confirm
    (confirmed_chain_ids) before a chain earns anything, no matter how many
    of its members line up."""
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}

    both_matched_unconfirmed = compute_metrics(
        [finding(10, matched=1), finding(11, matched=2)], vulns, [chain]
    )
    assert both_matched_unconfirmed["credit_by_chain"][7] == 0.0
    assert both_matched_unconfirmed["weighted_found"] == 18.0   # 9 + 9, no chain bonus
    assert both_matched_unconfirmed["weighted_total"] == 45.0   # chain still costs points unearned


def test_chain_credit_from_a_direct_finding_match_needs_no_separate_confirmation():
    """A finding matched DIRECTLY to the chain (matched_chain_id) is
    first-class evidence on its own — the scanner's own report contained one
    finding that itself identified the chain — so it credits immediately,
    with no confirmed_chain_ids entry and regardless of whether the
    individual members also show up as their own separate findings."""
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}

    # Neither member matched individually, but one finding names the chain directly.
    m = compute_metrics([finding(10, matched_chain=7)], vulns, [chain])
    assert m["credit_by_chain"][7] == 1.0
    assert m["weighted_found"] == 27.0
    assert m["weighted_total"] == 45.0


def test_finding_matched_directly_to_a_chain_is_not_pending():
    """Real incident (scan 273): precision showed a 92.6-100% range with '2
    pending', but the findings list showed zero pending rows. `pending` only
    checked `matched_vuln_id is None`, so a finding matched DIRECTLY to a
    chain (matched_vuln_id null, matched_chain_id set -- fully resolved, first
    -class evidence per test_chain_credit_from_a_direct_finding_match_needs_no_separate_confirmation
    above) was miscounted as still awaiting adjudication."""
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}

    m = compute_metrics([finding(10, matched_chain=7)], vulns, [chain])
    assert m["pending"] == 0
    assert m["adjudication_complete"] is True
    assert m["precision_upper"] == m["precision_lower"] == 0.0  # tp=0 (chains aren't vuln TPs), no FPs


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_weight_validation_enforces_the_scale():
    import pytest
    assert scoring.validate_weight(9) == 9
    assert scoring.validate_weight("27") == 27
    assert scoring.validate_weight(None) is None
    for bad in (2, 10, 0, -1, "high"):
        with pytest.raises(ValueError):
            scoring.validate_weight(bad)


def test_tier_validation():
    import pytest
    assert scoring.validate_tier("Business_Logic") == "business_logic"
    assert scoring.validate_tier(None) is None
    with pytest.raises(ValueError):
        scoring.validate_tier("hard")


def test_weight_falls_back_to_severity_then_default():
    assert scoring.weight_of({"severity": "critical"}) == 27
    assert scoring.weight_of({"severity": "info"}) == 1
    assert scoring.weight_of({"impact_weight": 9, "severity": "info"}) == 9
    assert scoring.weight_of({}) == scoring.DEFAULT_WEIGHT


def test_empty_corpus_does_not_divide_by_zero():
    m = compute_metrics([], [])
    assert m["weighted_rate"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1"] == 0.0
    assert m["severity_accuracy"] == 0.0
    assert m["severity_checked"] == 0


# ---------------------------------------------------------------------------
# Severity accuracy
# ---------------------------------------------------------------------------

def test_severity_accuracy_denominator_is_every_tp():
    v1 = vuln(1, 9, severity="high")
    v2 = vuln(2, 9, severity="high")
    findings = [
        finding(10, matched=1, severity="high"),   # correct
        finding(11, matched=2, severity="low"),    # matched, wrong severity
    ]
    m = compute_metrics(findings, [v1, v2])
    assert m["severity_checked"] == 2
    assert m["severity_correct"] == 1
    assert m["severity_accuracy"] == 0.5


def test_severity_accuracy_counts_missing_severity_against_the_scanner():
    v = vuln(1, 9, severity="high")
    # A TP whose finding never reported a severity DOES count against the
    # scanner: giving no usable rating is a failure to rate, not a neutral
    # non-event, so the denominator is always TP, not just the adjudicable
    # subset that happened to report something.
    m = compute_metrics([finding(10, matched=1, severity=None)], [v])
    assert m["severity_checked"] == 1
    assert m["severity_correct"] == 0
    assert m["severity_accuracy"] == 0.0


def test_severity_accuracy_is_case_insensitive_and_ignores_fp_and_pending():
    v = vuln(1, 9, severity="High")
    findings = [
        finding(10, matched=1, severity="HIGH"),
        finding(11, fp=1, severity="critical"),      # FP: not counted
        finding(12, matched=None, severity="medium"),  # pending: not counted
    ]
    m = compute_metrics(findings, [v])
    assert m["severity_checked"] == 1
    assert m["severity_correct"] == 1
    assert m["severity_accuracy"] == 1.0


# ---------------------------------------------------------------------------
# Multi-match findings (migration 040)
# ---------------------------------------------------------------------------
# Real incident (scan 330, TaintedPort): three findings — path traversal, SSRF
# and directory listing — each explicitly read api/config/jwt.php and quoted
# the hardcoded HS256 secret, but a finding could only be credited for ONE
# thing, so each was matched to its own access vuln and CODE-001 scored as a
# MISS the scan had demonstrated three times over. And a scan reporting one
# clean chain narrative naming its members got either the chain or one member,
# never both, while a scan that redundantly re-reported each member got
# everything. Matches are additive now; these lock in that it does not distort
# the metric.

def test_one_finding_crediting_three_vulns_equals_three_findings_crediting_one():
    """The symmetry that makes additive matches safe: the score depends on what
    was demonstrated, not on how the report was split up."""
    vulns = [vuln(1, 9), vuln(2, 9), vuln(3, 27)]

    bundled = compute_metrics([finding(10, matched_vulns=[1, 2, 3])], vulns)
    split = compute_metrics(
        [finding(10, matched=1), finding(11, matched=2), finding(12, matched=3)],
        vulns,
    )

    for key in ("tp", "fn", "fp_groups", "pending", "weighted_found",
                "weighted_total", "weighted_rate", "precision_upper", "recall"):
        assert bundled[key] == split[key], key
    assert bundled["tp"] == 3


def test_one_finding_can_credit_a_chain_and_its_members_at_once():
    """The case that was previously unexpressible: a report whose single
    finding walks the chain end to end AND names each member it used. The
    chain and the members are separate assertions, both credited."""
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}

    m = compute_metrics(
        [finding(10, matched_vulns=[1, 2], matched_chains=[7])], vulns, [chain]
    )

    assert m["tp"] == 2
    assert m["credit_by_chain"][7] == 1.0
    assert m["weighted_found"] == 9.0 + 9.0 + 27.0
    assert m["pending"] == 0


def test_a_chain_match_alone_still_does_not_credit_its_members():
    """Crediting the members stays an explicit assertion, never inferred from
    the chain match — the reviewer/importer has to say the finding actually
    demonstrated each one."""
    vulns = [vuln(1, 9), vuln(2, 9)]
    chain = {"id": 7, "impact_weight": 27, "members": [1, 2],
             "existed_since_revision": 1, "invalidated_at_revision": None}

    m = compute_metrics([finding(10, matched_chains=[7])], vulns, [chain])

    assert m["credit_by_chain"][7] == 1.0
    assert m["tp"] == 0
    assert m["fn"] == 2


def test_duplicate_credit_of_one_vuln_across_findings_counts_once():
    """Two findings both crediting the same vuln is one TP, not two — the
    scan-330 shape where several findings each read the same secret."""
    vulns = [vuln(1, 9), vuln(2, 3)]

    m = compute_metrics(
        [finding(10, matched_vulns=[1, 2]), finding(11, matched_vulns=[1])], vulns
    )

    assert m["tp"] == 2
    assert m["weighted_found"] == 12.0

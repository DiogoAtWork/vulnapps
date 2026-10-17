"""Ground-truth revision behaviour, end to end.

Service-level rather than HTTP, against a freshly migrated throwaway database:
these tests are about what the revision-scope axis guarantees, and every
service function takes its connection as an argument, so no global
DATABASE_PATH is involved and nothing here can disturb another test module.
"""

import os
import tempfile

import aiosqlite
import pytest
import pytest_asyncio

from app.database import run_migrations
from app.services import finding_matches
from app.services import scans as scans_service
from app.services import scoring as scoring_service
from app.services import vulns as vulns_service


ADMIN = {"sub": 1, "name": "tester", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "scoring.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute(
        "INSERT INTO users (id, name, email, password_hash, role) "
        "VALUES (1, 'tester', 't@example.com', 'x', 'admin')"
    )
    await conn.commit()
    yield conn
    await conn.close()


async def make_app(db, name="Target"):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES (?, '1.0', 1, 'private')",
        (name,),
    )
    await db.commit()
    return cursor.lastrowid


async def add_vuln(db, app_id, slug, severity="high", weight=9, tier="commodity",
                   vuln_type="SQLi", url="/a", existed_since=1):
    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, url, created_by,
            impact_weight, difficulty_tier, weight_verified,
            existed_since_revision, known_since_revision)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?, 1)""",
        (app_id, slug, f"Vuln {slug}", severity, vuln_type, url, weight, tier, existed_since),
    )
    await db.commit()
    return cursor.lastrowid


async def submit(db, app_id, findings, scanner_name="COS"):
    return await scans_service.submit_scan(
        db, ADMIN, app_id,
        scanner_name=scanner_name,
        scan_date="2026-07-01",
        is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=findings,
    )


async def _scan(db, scan_id):
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    return await cursor.fetchone()


# ---------------------------------------------------------------------------
# Submission records the corpus revision it ran against
# ---------------------------------------------------------------------------

async def test_submit_records_corpus_revision(db):
    app_id = await make_app(db)
    await add_vuln(db, app_id, "V-1", url="/login")
    scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login"}])
    scan = await _scan(db, scan_id)
    assert scan["corpus_revision"] == 1


# ---------------------------------------------------------------------------
# Promotion: the existed_since choice, and retroactive re-scoring
# ---------------------------------------------------------------------------

async def test_promotion_requires_the_existed_since_choice(db):
    app_id = await make_app(db)
    await add_vuln(db, app_id, "V-1", url="/login")
    scan_id = await submit(db, app_id, [{"vuln_type": "IDOR", "url": "/orders/1"}])
    cursor = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ?", (scan_id,))
    finding_id = (await cursor.fetchone())["id"]

    with pytest.raises(ValueError, match="existed_since"):
        await scans_service.promote_finding(db, ADMIN, scan_id, finding_id, {"title": "New"})


async def test_promoted_prior_vuln_lowers_recall_on_an_older_scan(db):
    """A vuln that existed all along makes an older scan's miss real once it
    is promoted into ground truth — recall is recomputed live, not frozen.
    ``existed_since_revision=1`` means "always in scope", so this reaches back
    regardless of which revision number you score at."""
    app_id = await make_app(db)
    await add_vuln(db, app_id, "V-1", url="/login", weight=9)

    old_scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login"}])
    old_scan = await _scan(db, old_scan_id)
    before = await scoring_service.score(db, old_scan, 1)
    assert before["metrics"]["recall"] == 1.0
    assert before["metrics"]["weighted_total"] == 9.0

    # A later scan finds something new; promote it as "existed all along".
    new_scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "url": "/login"},
        {"vuln_type": "IDOR", "url": "/orders/1", "title": "IDOR on orders",
         "severity": "critical"},
    ])
    cursor = await db.execute(
        "SELECT id FROM scan_findings sf WHERE sf.scan_id = ? AND NOT EXISTS "
        "(SELECT 1 FROM finding_matches fm WHERE fm.finding_id = sf.id)",
        (new_scan_id,),
    )
    finding_id = (await cursor.fetchone())["id"]
    result = await scans_service.promote_finding(
        db, ADMIN, new_scan_id, finding_id,
        {"title": "IDOR on orders", "severity": "critical", "existed_since": "all_along"},
    )
    assert result["revision"] == 2
    assert result["existed_since_revision"] == 1
    assert result["vuln"]["known_since_revision"] == 2
    assert result["vuln"]["impact_weight"] == 27      # derived from severity

    # Re-scoring the old scan now shows the miss it always deserved: 1 of 2
    # vulns, 9 of 36 points.
    latest = await scoring_service.latest_revision(db, app_id)
    after = await scoring_service.score(db, old_scan, latest)
    assert after["metrics"]["fn"] == 1
    assert after["metrics"]["recall"] == 0.5
    assert after["metrics"]["weighted_total"] == 36.0
    assert after["metrics"]["weighted_found"] == 9.0
    assert round(after["metrics"]["weighted_rate"], 4) == 0.25


async def test_promoted_new_code_vuln_leaves_prior_scans_alone(db):
    app_id = await make_app(db)
    await add_vuln(db, app_id, "V-1", url="/login", weight=9)
    old_scan_id = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login"}])
    old_scan = await _scan(db, old_scan_id)
    new_scan_id = await submit(db, app_id, [{"vuln_type": "IDOR", "url": "/orders/1"}])

    cursor = await db.execute(
        "SELECT id FROM scan_findings sf WHERE sf.scan_id = ? AND NOT EXISTS "
        "(SELECT 1 FROM finding_matches fm WHERE fm.finding_id = sf.id)",
        (new_scan_id,),
    )
    finding_id = (await cursor.fetchone())["id"]
    await scans_service.promote_finding(
        db, ADMIN, new_scan_id, finding_id,
        {"title": "Introduced by a refactor", "severity": "high",
         "existed_since": "this_revision"},
    )

    rev2 = await scoring_service.latest_revision(db, app_id)
    as_known = await scoring_service.score(db, old_scan, rev2)
    # The new vuln is not in scope at revision 2 for a corpus it postdates...
    assert as_known["metrics"]["weighted_total"] == 9.0
    assert as_known["metrics"]["recall"] == 1.0


# ---------------------------------------------------------------------------
# Weights, tiers and invalidation
# ---------------------------------------------------------------------------

async def test_weight_change_opens_a_revision(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "V-1", url="/login", weight=9)
    await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login"}])

    await vulns_service.inline_update_vuln(db, ADMIN, app_id, vuln_id, {"impact_weight": 27})

    revisions = await scoring_service.list_revisions(db, app_id)
    assert [r["reason"] for r in revisions] == ["corpus_change", "weight_change"]
    assert await scoring_service.latest_revision(db, app_id) == 2


async def test_update_without_scoring_fields_preserves_a_hand_set_weight(db):
    """An older client (or the inline table editor) sending only the columns it
    knows about must not reset a corrected weight to the severity default."""
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "V-1", severity="medium", weight=27,
                             tier="business_logic")

    await vulns_service.update_vuln(db, ADMIN, app_id, vuln_id, {
        "vuln_id": "V-1", "title": "Renamed", "severity": "medium", "vuln_type": "SQLi",
    })

    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = await cursor.fetchone()
    assert row["title"] == "Renamed"
    assert row["impact_weight"] == 27              # not reset to 3 (medium)
    assert row["difficulty_tier"] == "business_logic"
    # And no spurious weight_change revision was opened.
    assert await scoring_service.latest_revision(db, app_id) == 1


async def test_invalid_weight_is_rejected(db):
    app_id = await make_app(db)
    with pytest.raises(ValueError, match="must be one of"):
        await vulns_service.create_vuln(db, ADMIN, app_id, {
            "vuln_id": "V-9", "title": "x", "severity": "high", "impact_weight": 5,
        })


async def test_authoring_ground_truth_before_any_scan_does_not_spawn_revisions(db):
    app_id = await make_app(db)
    for i in range(3):
        await vulns_service.create_vuln(db, ADMIN, app_id, {
            "vuln_id": f"V-{i}", "title": "x", "severity": "high",
            "difficulty_tier": "business_logic",
        })
    # Nothing to re-score yet, so no revision churn.
    assert await scoring_service.latest_revision(db, app_id) == 1
    assert len(await scoring_service.list_revisions(db, app_id)) == 1


async def test_invalidation_keeps_earlier_revisions_reproducible(db):
    app_id = await make_app(db)
    keep = await add_vuln(db, app_id, "V-1", url="/login", weight=9)
    drop = await add_vuln(db, app_id, "V-2", url="/search", weight=9)
    scan_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "url": "/login"},
        {"vuln_type": "SQLi", "url": "/search"},
    ])
    scan = await _scan(db, scan_id)
    original = await scoring_service.score(db, scan, 1)
    assert original["metrics"]["weighted_total"] == 18.0

    await vulns_service.invalidate_vuln(db, ADMIN, app_id, drop, "not actually a flaw")

    # Revision 1 is untouched...
    still_rev1 = await scoring_service.score(db, scan, 1)
    assert still_rev1["metrics"]["weighted_total"] == 18.0

    rev2 = await scoring_service.latest_revision(db, app_id)
    assert rev2 == 2
    # ...but the dropped vuln leaves scope from revision 2 on.
    at_rev2 = await scoring_service.score(db, scan, rev2)
    assert at_rev2["metrics"]["weighted_total"] == 9.0
    assert at_rev2["metrics"]["tp"] == 1
    # The finding that matched the invalidated vuln is neither TP nor FP now.
    assert at_rev2["metrics"]["out_of_scope_matches"] == 1
    assert keep in at_rev2["metrics"]["matched_vuln_ids"]


async def test_matched_vuln_cannot_be_deleted(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "V-1", url="/login")
    await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login"}])
    with pytest.raises(ValueError, match="cannot be deleted"):
        await vulns_service.delete_vuln(db, ADMIN, app_id, vuln_id)


# ---------------------------------------------------------------------------
# Reporting guards (comparison view)
# ---------------------------------------------------------------------------

async def test_compare_suppresses_precision_when_adjudication_is_incomplete(db):
    app_id = await make_app(db)
    await add_vuln(db, app_id, "V-1", url="/login")
    a = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/login"}])
    b = await submit(db, app_id, [
        {"vuln_type": "SQLi", "url": "/login"},
        {"vuln_type": "XSS", "url": "/unknown"},
    ])
    result = await scans_service.compare_scans(db, ADMIN, app_id, [a, b])
    assert result["guards"]["suppress_precision"] is True
    assert result["guards"]["adjudication_incomplete_scans"] == [b]
    scanner_b = [s for s in result["scanners"] if s["scan"]["id"] == b][0]
    assert scanner_b["metrics"]["precision_lower"] < scanner_b["metrics"]["precision_upper"]


# ---------------------------------------------------------------------------
# Chains through the service layer
# ---------------------------------------------------------------------------

async def test_chain_participates_in_the_scope_rule(db):
    app_id = await make_app(db)
    v1 = await add_vuln(db, app_id, "V-1", url="/login", weight=9)
    v2 = await add_vuln(db, app_id, "V-2", url="/search", weight=9)
    findings = [{"vuln_type": "SQLi", "url": "/login"},
                {"vuln_type": "SQLi", "url": "/search"}]

    # A scan that ran before the chain was documented as ground truth.
    early_scan_id = await submit(db, app_id, findings)

    # Document the chain from revision 2 on.
    revision = await scoring_service.create_revision(db, app_id, "corpus_change", "add chain")
    cursor = await db.execute(
        """INSERT INTO chains (app_id, chain_id, title, impact_weight,
                               existed_since_revision, invalidated_at_revision)
           VALUES (?, 'C-1', 'SQLi to takeover', 27, ?, NULL)""",
        (app_id, revision),
    )
    chain_pk = cursor.lastrowid
    for order, vid in enumerate([v1, v2]):
        await db.execute(
            "INSERT INTO chain_members (chain_pk, vuln_id, step_order) VALUES (?, ?, ?)",
            (chain_pk, vid, order),
        )
    await db.commit()

    assert await scoring_service.fetch_chains_in_scope(db, app_id, 1) == []
    at_two = await scoring_service.fetch_chains_in_scope(db, app_id, 2)
    assert len(at_two) == 1
    assert at_two[0]["members"] == [v1, v2]

    # The chain is not in scope for the earlier scan even at revision 2 — it
    # postdates that run, exactly like a vuln introduced by a code change.
    early_scan = await _scan(db, early_scan_id)
    early = await scoring_service.score(db, early_scan, 2)
    assert early["metrics"]["weighted_total"] == 18.0

    later_scan_id = await submit(db, app_id, findings)
    # Matching every member is necessary but not sufficient — a reviewer must
    # also explicitly confirm this scan demonstrates the chain (migration 038).
    await db.execute(
        "INSERT INTO scan_chain_credits (scan_id, chain_pk, credited_by) VALUES (?, ?, 1)",
        (later_scan_id, chain_pk),
    )
    await db.commit()
    later_scan = await _scan(db, later_scan_id)
    scored = await scoring_service.score(db, later_scan, 2)
    assert scored["metrics"]["weighted_total"] == 45.0     # 9 + 9 + 27
    # Both members matched AND explicitly confirmed → the chain earns its
    # full weight (no partial credit; there is no chain-level milestone
    # tracking).
    assert scored["metrics"]["weighted_found"] == 45.0
    assert scored["metrics"]["tiers"]["chained"]["count"] == 1
    assert scored["metrics"]["tiers"]["chained"]["found"] == 1


# ---------------------------------------------------------------------------
# Tool-reported severity survives the round trip
# ---------------------------------------------------------------------------

async def test_finding_severity_survives_a_match(db):
    """If anything normalised finding severity, or overwrote it with the
    ground-truth severity on a match, the tool's own assessment would be
    silently lost."""
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "V-1", severity="critical", weight=27,
                             url="/files/", vuln_type="Information Disclosure")

    # A DAST-style import: right location, conventional severity.
    scan_id = await submit(db, app_id, [{
        "vuln_type": "Information Disclosure", "url": "/files/",
        "title": "Directory listing", "severity": "low",
    }])

    cursor = await db.execute("SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,))
    finding = (await finding_matches.attach(db, await cursor.fetchall()))[0]
    assert finding["matched_vuln_ids"] == [vuln_id]   # it matched...
    assert finding["severity"] == "low"              # ...and kept what the tool said

    # Re-matching by hand must not rewrite it either.
    await scans_service.match_finding(db, ADMIN, scan_id, finding["id"], [vuln_id], [])
    cursor = await db.execute("SELECT severity FROM scan_findings WHERE id = ?", (finding["id"],))
    assert (await cursor.fetchone())["severity"] == "low"


# ---------------------------------------------------------------------------
# Weight derives from severity
# ---------------------------------------------------------------------------

async def test_changing_severity_re_derives_the_weight_and_opens_a_revision(db):
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "V-1", severity="medium", weight=3)
    await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/a"}])

    # Severity is the weight, so an inline severity edit re-derives it.
    await vulns_service.update_vuln(db, ADMIN, app_id, vuln_id, {
        "vuln_id": "V-1", "title": "Vuln V-1", "severity": "critical", "vuln_type": "SQLi",
    })

    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = await cursor.fetchone()
    assert row["impact_weight"] == 27
    revisions = await scoring_service.list_revisions(db, app_id)
    assert revisions[-1]["reason"] == "weight_change"


async def test_an_explicit_weight_override_survives_an_unrelated_edit(db):
    """Overrides are exceptional but must not be silently undone."""
    app_id = await make_app(db)
    vuln_id = await add_vuln(db, app_id, "V-1", severity="medium", weight=27)

    await vulns_service.update_vuln(db, ADMIN, app_id, vuln_id, {
        "vuln_id": "V-1", "title": "Renamed", "severity": "medium", "vuln_type": "SQLi",
    })
    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    assert (await cursor.fetchone())["impact_weight"] == 27


async def test_scan_list_metrics_match_live_scoring_across_corpora_and_chain_credit(db):
    app_id = await make_app(db)
    v1 = await add_vuln(db, app_id, "V-1", weight=9, url="/first")
    v2 = await add_vuln(db, app_id, "V-2", weight=3, url="/second")
    cursor = await db.execute(
        "INSERT INTO chains (app_id, chain_id, title, impact_weight, existed_since_revision) "
        "VALUES (?, 'C-1', 'Demo chain', 27, 1)", (app_id,),
    )
    chain_id = cursor.lastrowid
    await db.executemany(
        "INSERT INTO chain_members (chain_pk, vuln_id, step_order) VALUES (?, ?, ?)",
        [(chain_id, v1, 1), (chain_id, v2, 2)],
    )
    await db.commit()
    partial_id = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/first"}])
    full_id = await submit(db, app_id, [
        {"vuln_type": "SQLi", "url": "/first"}, {"vuln_type": "SQLi", "url": "/second"},
    ])
    await db.execute(
        "INSERT INTO scan_chain_credits (scan_id, chain_pk, credited_by) VALUES (?, ?, 1)",
        (full_id, chain_id),
    )
    direct_id = await submit(db, app_id, [{"vuln_type": "IDOR", "url": "/chain"}])
    cursor = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ?", (direct_id,))
    await finding_matches.replace(db, (await cursor.fetchone())["id"], [], [chain_id])
    await scoring_service.create_revision(db, app_id, "corpus_change", "new application flaw")
    await add_vuln(db, app_id, "V-3", weight=27, url="/new", existed_since=2)
    later_id = await submit(db, app_id, [{"vuln_type": "SQLi", "url": "/new"}])
    empty_app = await make_app(db, "Empty corpus")
    await db.execute("UPDATE apps SET version = '2.0' WHERE id = ?", (empty_app,))
    empty_id = await submit(db, empty_app, [])
    await db.commit()

    ordinary = await scans_service.list_scans(db, ADMIN)
    assert all("metrics" not in scan.keys() for scan in ordinary["scans"])
    result = await scans_service.list_scans(db, ADMIN, include_metrics=True)
    scans = {scan["id"]: scan for scan in result["scans"]}
    for scan in scans.values():
        revision = await scoring_service.latest_revision(db, scan["app_id"])
        expected = (await scoring_service.score(db, scan, revision))["metrics"]
        assert scan["metrics"]
        for key, value in scan["metrics"].items():
            assert value == expected[key], (scan["id"], key)
            assert isinstance(value, (int, float, bool)) or (
                value is None and key in {
                    "weighted_precision", "weighted_precision_upper", "weighted_f05", "weighted_f05_upper"
                }
            )
    # Partial chain members receive only their own points, never inferred chain credit.
    assert scans[partial_id]["metrics"]["weighted_found"] == 9
    assert scans[partial_id]["metrics"]["weighted_total"] == 39
    assert scans[full_id]["metrics"]["weighted_found"] == 39
    assert scans[direct_id]["metrics"]["weighted_found"] == 27
    assert scans[later_id]["metrics"]["weighted_total"] == 66
    assert scans[empty_id]["metrics"]["weighted_total"] == 0
    assert scans[empty_id]["metrics"]["weighted_rate"] == 0
    assert (await scans_service.list_scans(db, None, include_metrics=True))["scans"] == []

"""Service-level tests for many-to-many finding matches (migration 040).

A finding can demonstrate several things at once. Real incident (scan 330,
TaintedPort): three findings — path traversal, SSRF and directory listing —
each explicitly read api/config/jwt.php and quoted the hardcoded HS256 secret,
but a finding could be credited for exactly ONE thing, so each was matched to
its own access vuln and CODE-001 scored as a miss the scan had demonstrated
three times over. Fixing it by hand meant re-pointing a finding, which cost
its original vuln a piece of evidence — a trade, not a fix.

Same throwaway-DB convention as tests/test_audit_log.py.
"""

import os
import tempfile

import aiosqlite
import pytest_asyncio

from app.database import run_migrations
from app.services import finding_matches
from app.services import scans as scans_service

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "matches.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute(
        "INSERT INTO users (id, name, email, password_hash, role) "
        "VALUES (1, 'Nuno', 't@example.com', 'x', 'admin')"
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


async def add_vuln(db, app_id, slug, url="/a", vuln_type="SQLi"):
    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, url, created_by,
            impact_weight, difficulty_tier, weight_verified,
            existed_since_revision, known_since_revision)
           VALUES (?, ?, ?, 'high', ?, ?, 1, 9, 'commodity', 1, 1, 1)""",
        (app_id, slug, f"Vuln {slug}", vuln_type, url),
    )
    await db.commit()
    return cursor.lastrowid


async def add_chain(db, app_id, slug, member_ids):
    cursor = await db.execute(
        "INSERT INTO chains (app_id, chain_id, title, impact_weight, existed_since_revision) "
        "VALUES (?, ?, ?, 27, 1)",
        (app_id, slug, f"Chain {slug}"),
    )
    chain_pk = cursor.lastrowid
    for order, vid in enumerate(member_ids, start=1):
        await db.execute(
            "INSERT INTO chain_members (chain_pk, vuln_id, step_order) VALUES (?, ?, ?)",
            (chain_pk, vid, order),
        )
    await db.commit()
    return chain_pk


async def submit(db, app_id, findings):
    return await scans_service.submit_scan(
        db, ADMIN, app_id,
        scanner_name="COS", scan_date="2026-09-24", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=findings,
    )


async def only_finding(db, scan_id):
    cursor = await db.execute(
        "SELECT id FROM scan_findings WHERE scan_id = ? ORDER BY id LIMIT 1", (scan_id,)
    )
    return (await cursor.fetchone())["id"]


# ---------------------------------------------------------------------------

async def test_one_finding_matches_several_vulns(db):
    """The scan-330 shape: one file read proves both the access bug and that
    the file it read contains a hardcoded secret."""
    app_id = await make_app(db)
    traversal = await add_vuln(db, app_id, "TP-014", url="/files/")
    secret = await add_vuln(db, app_id, "CODE-001", url="/config", vuln_type="Hardcoded Secret")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "read jwt.php"}])
    fid = await only_finding(db, scan_id)

    result = await scans_service.match_finding(
        db, ADMIN, scan_id, fid, [traversal, secret], []
    )

    assert sorted(result["matched_vuln_ids"]) == sorted([traversal, secret])
    loaded = (await finding_matches.load(db, [fid]))[fid]
    assert sorted(loaded["vuln_ids"]) == sorted([traversal, secret])
    assert loaded["chain_ids"] == []


async def test_one_finding_matches_a_chain_and_its_members(db):
    """A report whose single finding walks the chain end to end and names each
    member it used — previously inexpressible, the chain and the members had
    to compete for the one slot."""
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-027", url="/import")
    b = await add_vuln(db, app_id, "CODE-001", url="/config")
    chain_pk = await add_chain(db, app_id, "CHAIN-004", [a, b])
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "ssrf to forged token"}])
    fid = await only_finding(db, scan_id)

    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a, b], [chain_pk])

    loaded = (await finding_matches.load(db, [fid]))[fid]
    assert sorted(loaded["vuln_ids"]) == sorted([a, b])
    assert loaded["chain_ids"] == [chain_pk]


async def test_matching_is_full_replacement(db):
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001")
    b = await add_vuln(db, app_id, "TP-002", url="/b")
    c = await add_vuln(db, app_id, "TP-003", url="/c")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)

    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a, b], [])
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [c], [])

    loaded = (await finding_matches.load(db, [fid]))[fid]
    assert loaded["vuln_ids"] == [c]


async def test_repeated_ids_are_deduplicated(db):
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)

    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a, a, a], [])

    assert (await finding_matches.load(db, [fid]))[fid]["vuln_ids"] == [a]


async def test_marking_fp_drops_every_match(db):
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001")
    b = await add_vuln(db, app_id, "TP-002", url="/b")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a, b], [])

    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid)

    assert (await finding_matches.load(db, [fid]))[fid] == {"vuln_ids": [], "chain_ids": []}


async def test_ignoring_drops_every_match(db):
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a], [])

    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, True)

    assert (await finding_matches.load(db, [fid]))[fid]["vuln_ids"] == []


async def test_clearing_with_empty_lists_returns_to_pending(db):
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a], [])

    result = await scans_service.match_finding(db, ADMIN, scan_id, fid, [], [])

    assert result["matched_vuln_ids"] == []
    assert result["matched_vuln_id"] is None      # legacy scalar for old clients
    assert (await finding_matches.load(db, [fid]))[fid]["vuln_ids"] == []


async def test_a_vuln_from_another_app_is_refused(db):
    """vuln-0004: a finding must never reference ground truth from an app the
    caller may not be allowed to read."""
    app_id = await make_app(db)
    other_app = await make_app(db, name="Other")
    mine = await add_vuln(db, app_id, "TP-001")
    theirs = await add_vuln(db, other_app, "TP-001", url="/x")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)

    try:
        await scans_service.match_finding(db, ADMIN, scan_id, fid, [mine, theirs], [])
        raise AssertionError("expected a refusal")
    except ValueError as e:
        assert "not found" in str(e).lower()

    # Nothing partially applied.
    assert (await finding_matches.load(db, [fid]))[fid]["vuln_ids"] == []


async def test_deleting_a_finding_cascades_its_matches(db):
    app_id = await make_app(db)
    a = await add_vuln(db, app_id, "TP-001")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "F"}])
    fid = await only_finding(db, scan_id)
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [a], [])

    await db.execute("DELETE FROM scan_findings WHERE id = ?", (fid,))
    await db.commit()

    cursor = await db.execute(
        "SELECT COUNT(*) AS c FROM finding_matches WHERE finding_id = ?", (fid,)
    )
    assert (await cursor.fetchone())["c"] == 0


async def test_reviewer_fp_penalty_persists_is_audited_and_requires_scan_write(db):
    import json
    import pytest
    from app.services import audit, scoring as scoring_service

    app_id = await make_app(db)
    await add_vuln(db, app_id, "KNOWN")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "Noise"}])
    fid = await only_finding(db, scan_id)
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, fp_impact_weight=3)
    scored = await scoring_service.score_many(db, [{"id": scan_id, "app_id": app_id}])
    assert scored[scan_id]["weighted_fp_penalty"] == 3
    assert scored[scan_id]["weighted_score_provisional"] is False
    events = await audit.list_audit_events(db, scan_id=scan_id)
    assert json.loads(events[0]["details"])["fp_impact_weight"] == 3
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, fp_group="same")
    row = await (await db.execute("SELECT * FROM scan_findings WHERE id = ?", (fid,))).fetchone()
    assert row["fp_impact_weight"] == 3
    for invalid in (True, "3", 2, 3.0):
        with pytest.raises(ValueError, match="fp_impact_weight"):
            await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, fp_impact_weight=invalid)
    with pytest.raises(PermissionError):
        await scans_service.mark_finding_fp(db, {"sub": 99, "role": "user"}, scan_id, fid, fp_impact_weight=1)
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, fp_impact_weight=None)
    scored = await scoring_service.score_many(db, [{"id": scan_id, "app_id": app_id}])
    assert scored[scan_id]["weighted_fp_penalty"] == 27
    assert scored[scan_id]["weighted_fp_unreviewed"] == 1
    await scans_service.set_finding_ignored(db, ADMIN, scan_id, fid, True)
    row = await (await db.execute("SELECT * FROM scan_findings WHERE id = ?", (fid,))).fetchone()
    assert row["fp_impact_weight"] is None


async def test_rematch_clears_penalty_before_a_new_fp_decision(db):
    from app.services import scoring as scoring_service

    app_id = await make_app(db)
    await add_vuln(db, app_id, "KNOWN")
    scan_id = await submit(db, app_id, [{"vuln_type": "Other", "title": "Noise"}])
    fid = await only_finding(db, scan_id)
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, fp_group="noise", fp_impact_weight=1)
    assert (await scans_service.rematch_scan(db, ADMIN, scan_id))["updated"] == 1
    row = await (await db.execute("SELECT * FROM scan_findings WHERE id = ?", (fid,))).fetchone()
    assert row["is_false_positive"] == 0
    assert row["fp_impact_weight"] is None
    assert row["fp_group"] is None
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid)
    metrics = (await scoring_service.score_many(db, [{"id": scan_id, "app_id": app_id}]))[scan_id]
    assert metrics["weighted_fp_unreviewed"] == 1
    assert metrics["weighted_score_provisional"] is True

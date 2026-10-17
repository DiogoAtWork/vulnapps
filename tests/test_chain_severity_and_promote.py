"""Chain severity, and promoting a finding to a chain the catalog is missing.

Scan 330 (TaintedPort, COS): the scanner reported four chains; the three not
in the catalog could only be marked FP, which charged it for real
discoveries (3 of its 5 FP groups). And every chain read as Critical because
chains stored only a weight. Same throwaway-DB convention as
tests/test_finding_matches.py.
"""

import os
import tempfile

import aiosqlite
import pytest
import pytest_asyncio

from app.database import run_migrations
from app.services import chains as chains_service
from app.services import finding_matches
from app.services import scans as scans_service
from app.services import scoring as scoring_service

ADMIN = {"sub": 1, "name": "Nuno", "role": "admin", "scope": "full"}


@pytest_asyncio.fixture
async def db():
    path = os.path.join(tempfile.mkdtemp(), "chains.db")
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await run_migrations(conn)
    await conn.execute(
        "INSERT INTO users (id, name, email, password_hash, role) VALUES (1, 'Nuno', 't@example.com', 'x', 'admin')"
    )
    await conn.commit()
    yield conn
    await conn.close()


async def setup(db):
    cursor = await db.execute(
        "INSERT INTO apps (name, version, created_by, visibility) VALUES ('T', '1.0', 1, 'private')"
    )
    app_id = cursor.lastrowid
    ids = []
    for slug in ("TP-017", "TP-024", "TP-020"):
        cursor = await db.execute(
            """INSERT INTO vulnerabilities (app_id, vuln_id, title, severity, vuln_type, url, created_by,
               impact_weight, difficulty_tier, weight_verified, existed_since_revision, known_since_revision)
               VALUES (?, ?, ?, 'high', 'IDOR', ?, 1, 9, 'business_logic', 1, 1, 1)""",
            (app_id, slug, f"Vuln {slug}", f"/{slug}"),
        )
        ids.append(cursor.lastrowid)
    await db.commit()
    return app_id, ids


async def test_severity_sets_the_weight(db):
    app_id, (a, b, _) = await setup(db)
    chain = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to B", "severity": "high", "member_vuln_ids": [a, b],
    })
    assert (chain["severity"], chain["impact_weight"]) == ("high", 9)


async def test_weight_only_callers_still_work(db):
    """The pre-041 API sent impact_weight; the severity is derived back."""
    app_id, (a, b, _) = await setup(db)
    chain = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to B", "impact_weight": 27, "member_vuln_ids": [a, b],
    })
    assert (chain["severity"], chain["impact_weight"]) == ("critical", 27)


async def test_changing_severity_rederives_weight_and_opens_a_revision(db):
    app_id, (a, b, _) = await setup(db)
    chain = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to B", "severity": "critical", "member_vuln_ids": [a, b],
    })
    await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-09-28", is_public=0,
        notes=None, cost=None, tokens=None, duration=None, findings_data=[],
    )
    before = await scoring_service.latest_revision(db, app_id)

    updated = await chains_service.update_chain(db, ADMIN, app_id, chain["id"], {"severity": "medium"})

    assert (updated["severity"], updated["impact_weight"]) == ("medium", 3)
    assert await scoring_service.latest_revision(db, app_id) > before, \
        "a weight change is a ground-truth change and must open a revision"


async def test_invalid_severity_is_rejected(db):
    app_id, (a, b, _) = await setup(db)
    with pytest.raises(ValueError, match="severity must be one of"):
        await chains_service.create_chain(db, ADMIN, app_id, {
            "title": "x", "severity": "extreme", "member_vuln_ids": [a, b],
        })


async def test_promote_fp_finding_to_a_new_chain(db):
    """The scan-330 case end to end: an FP'd chain report becomes a TP."""
    app_id, (leak, bopla, twofa) = await setup(db)
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="COS", scan_date="2026-09-28", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{"vuln_type": "Chain", "title": "Horizontal-to-vertical takeover"}],
    )
    cursor = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ?", (scan_id,))
    fid = (await cursor.fetchone())["id"]
    await scans_service.match_finding(db, ADMIN, scan_id, fid, [leak, bopla], [])
    await scans_service.mark_finding_fp(db, ADMIN, scan_id, fid, fp_impact_weight=1)

    result = await scans_service.promote_finding_to_chain(db, ADMIN, scan_id, fid, {
        "severity": "high", "member_vuln_ids": [leak, bopla, twofa],
    })

    chain = result["chain"]
    assert chain["title"] == "Horizontal-to-vertical takeover", "title defaults from the finding"
    assert (chain["severity"], [m["vuln_id"] for m in chain["members"]]) == ("high", [leak, bopla, twofa])
    cursor = await db.execute(
        "SELECT is_chain, is_false_positive, is_ignored, fp_impact_weight FROM scan_findings WHERE id = ?", (fid,)
    )
    row = await cursor.fetchone()
    assert (row["is_chain"], row["is_false_positive"], row["is_ignored"]) == (1, 0, 0)
    assert row["fp_impact_weight"] is None
    matches = (await finding_matches.load(db, [fid]))[fid]
    assert matches["chain_ids"] == [chain["id"]]


async def test_promote_keeps_the_vulns_the_finding_already_credits(db):
    app_id, (leak, bopla, twofa) = await setup(db)
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="COS", scan_date="2026-09-28", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{"vuln_type": "Chain", "title": "c", "is_chain": True}],
    )
    cursor = await db.execute("SELECT id, is_chain FROM scan_findings WHERE scan_id = ?", (scan_id,))
    row = await cursor.fetchone()
    assert row["is_chain"] == 1, "submit stores the importer's flag"
    await scans_service.match_finding(db, ADMIN, scan_id, row["id"], [leak, twofa], [])

    await scans_service.promote_finding_to_chain(db, ADMIN, scan_id, row["id"], {
        "severity": "high", "member_vuln_ids": [leak, bopla, twofa],
    })

    matches = (await finding_matches.load(db, [row["id"]]))[row["id"]]
    assert sorted(matches["vuln_ids"]) == sorted([leak, twofa])
    assert len(matches["chain_ids"]) == 1


async def test_mapping_a_finding_to_a_chain_marks_it_a_chain_report(db):
    app_id, (a, b, _) = await setup(db)
    chain = await chains_service.create_chain(db, ADMIN, app_id, {
        "title": "A to B", "severity": "high", "member_vuln_ids": [a, b],
    })
    scan_id = await scans_service.submit_scan(
        db, ADMIN, app_id, scanner_name="S", scan_date="2026-09-28", is_public=0,
        notes=None, cost=None, tokens=None, duration=None,
        findings_data=[{"vuln_type": "x", "title": "missed by the importer"}],
    )
    cursor = await db.execute("SELECT id FROM scan_findings WHERE scan_id = ?", (scan_id,))
    fid = (await cursor.fetchone())["id"]

    await scans_service.match_finding(db, ADMIN, scan_id, fid, [], [chain["id"]])

    cursor = await db.execute("SELECT is_chain FROM scan_findings WHERE id = ?", (fid,))
    assert (await cursor.fetchone())["is_chain"] == 1

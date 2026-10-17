from __future__ import annotations

import hashlib
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

from app.config import STATE_DIR, MAX_STATE_SIZE
from app.matching import match_finding as match_finding_algo
from app.visibility import scan_visibility_filter
from app.dependencies import get_team_role
from app import scoring
from app.services import audit as audit_service
from app.services import finding_matches
from app.services import scoring as scoring_service


# ---------------------------------------------------------------------------
# Permission helpers (no HTTP dependencies)
# ---------------------------------------------------------------------------

async def _check_scan_write(db, user, scan, app) -> None:
    """Raise PermissionError if user cannot write to this scan."""
    if not user:
        raise PermissionError("Not authenticated")
    if user["role"] == "admin":
        return
    if scan["submitted_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return
    raise PermissionError("You don't have write access to this scan")


async def _check_app_write(db, user, app) -> None:
    """Raise PermissionError if user lacks app-write access (mirrors vulns._require_app_write)."""
    if not user:
        raise PermissionError("Authentication required")
    if user["role"] == "admin":
        return
    if app["visibility"] == "public":
        raise PermissionError("Only admins can edit public apps")
    if app["created_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return
    raise PermissionError("You don't have write access to this app")


async def _check_scan_submit(db, user, app) -> None:
    """Raise PermissionError if user cannot submit scans on this app."""
    if not user:
        raise PermissionError("Not authenticated")
    if user["role"] == "admin":
        return
    if app["visibility"] == "public":
        raise PermissionError("Only admins can submit scans on public apps")
    if app["visibility"] == "private" and app["created_by"] != user["sub"]:
        raise PermissionError("Only the app creator can submit scans on private apps")
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role not in ("admin", "contributor"):
            raise PermissionError("Team contributor access required to submit scans")


async def _get_scan_and_app(db, scan_id):
    """Fetch scan and its app. Raises ValueError if not found."""
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = await cursor.fetchone()
    if not scan:
        raise ValueError("Scan not found")
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
    app = await cursor.fetchone()
    return scan, app


async def _check_scan_view(db, user, scan, app) -> None:
    """Raise PermissionError if user cannot view this scan.

    Mirrors the inline check in get_scan(): admins always; otherwise public
    scans on public apps, the submitter, or any member of the app's team.
    """
    if not user:
        if not (scan["is_public"] and app["visibility"] == "public"):
            raise PermissionError("Not authenticated")
        return
    if user["role"] == "admin":
        return
    if scan["is_public"]:
        return
    if scan["submitted_by"] == user["sub"]:
        return
    if app["visibility"] == "team" and app["team_id"]:
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role is not None:
            return
    raise PermissionError("Access denied")


def _as_int(value):
    """Coerce to int, or None. Config fields arrive from JSON bodies and CLIs."""
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _live_metrics(db, scan, revision=None):
    """Metrics for *scan* as they stand right now (the UI's "current" view).

    Delegates to the single pure implementation in :mod:`app.scoring`; the only
    job here is fetching the right inputs. Numbers that leave the tool come from
    a ``scorings`` row instead — see :mod:`app.services.scoring`.
    """
    if revision is None:
        revision = await scoring_service.latest_revision(db, scan["app_id"])
    result = await scoring_service.score(db, scan, revision)
    vulns_by_id = {v["id"]: v for v in result["vulns"]}
    missed = [vulns_by_id[vid] for vid in result["metrics"]["missed_vuln_ids"] if vid in vulns_by_id]
    return result, missed


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

def _scan_with_cost_permission(scan, can_view_cost):
    scan_out = dict(scan)
    if not can_view_cost:
        for key in ("cost", "tokens", "duration", "notes"):
            scan_out[key] = None
    return scan_out


async def list_scans(
    db, user,
    app_id=None, scanner="", latest="", q="",
    label="", filter="", label_match="all", include_metrics=False,
) -> dict:
    """List scans with filters. Returns dict with scans, metadata, and filter options."""
    extra_filters = ""
    extra_params = []
    app = None

    if app_id:
        extra_filters += " AND scans.app_id = ?"
        extra_params.append(app_id)
        cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app = await cursor.fetchone()

    if filter == "public":
        extra_filters += " AND apps.visibility = 'public'"
    elif filter == "private":
        extra_filters += " AND apps.visibility = 'private'"
    elif filter == "teams":
        extra_filters += " AND apps.visibility = 'team'"
    elif filter and filter.startswith("team:") and user:
        try:
            tid = int(filter[5:])
            extra_filters += " AND apps.team_id = ?"
            extra_params.append(tid)
        except ValueError:
            pass

    if scanner:
        extra_filters += " AND scans.scanner_name = ?"
        extra_params.append(scanner)


    if label_match not in ("all", "any"):
        raise ValueError("label_match must be 'all' or 'any'")
    selected_labels = list(dict.fromkeys(
        name for name in ([label] if isinstance(label, str) else label or []) if name
    ))
    if selected_labels:
        placeholders = ",".join("?" for _ in selected_labels)
        extra_filters += (
            " AND scans.id IN ("
            "SELECT scan_id FROM scan_labels JOIN labels ON scan_labels.label_id = labels.id "
            f"WHERE labels.name IN ({placeholders})"
        )
        extra_params.extend(selected_labels)
        if label_match == "all":
            extra_filters += " GROUP BY scan_id HAVING COUNT(DISTINCT labels.name) = ?"
            extra_params.append(len(selected_labels))
        extra_filters += ")"

    if q:
        extra_filters += " AND (apps.name LIKE ? OR scans.scanner_name LIKE ? OR users.name LIKE ?)"
        q_like = f"%{q}%"
        extra_params.extend([q_like, q_like, q_like])

    vis_clause, vis_params = scan_visibility_filter(user)

    # Severity counts use COALESCE(finding.severity, vuln.severity) so a TP
    # finding (whose severity is usually empty by design — the LLM was told
    # to leave it blank for matched findings) still contributes through the
    # severity carried on the matched vulnerability. FP findings are
    # excluded — the user explicitly marked them as not-real.
    # A finding can match several vulns (migration 040), so the vuln-severity
    # fallback takes the highest-weighted matched vuln rather than "the" one.
    sev_subquery = (
        "(SELECT COUNT(*) FROM scan_findings sf "
        "WHERE sf.scan_id = scans.id AND sf.is_false_positive = 0 AND sf.is_ignored = 0 "
        "AND lower(COALESCE(NULLIF(sf.severity, ''), ("
        "  SELECT v.severity FROM finding_matches fm "
        "  JOIN vulnerabilities v ON v.id = fm.vuln_id "
        "  WHERE fm.finding_id = sf.id AND fm.vuln_id IS NOT NULL "
        "  ORDER BY v.impact_weight DESC LIMIT 1"
        "))) = ?)"
    )

    # The list view is a "current" view: scoped to the app's latest revision,
    # which for vulns reduces to "not invalidated" (nothing can have an
    # existed_since or invalidated_at above the newest revision). fp_count is
    # the CLUSTERED count — distinct fp_group values plus one per ungrouped FP —
    # so TP and FP are finally counted at the same granularity.
    tp_subquery = (
        "(SELECT COUNT(DISTINCT fm.vuln_id) FROM scan_findings sf "
        "JOIN finding_matches fm ON fm.finding_id = sf.id "
        "JOIN vulnerabilities v ON v.id = fm.vuln_id "
        "WHERE sf.scan_id = scans.id AND v.invalidated_at_revision IS NULL)"
    )
    # TP split by the CATALOG's severity, not the scanner's reported one: these
    # are distinct matched vulns, and the vuln row is the thing that carries the
    # authoritative severity (it is also what the weights use). Deliberately the
    # same scope as tp_subquery so the four buckets always sum to tp_count --
    # a breakdown that disagreed with the number beside it would be worse than
    # no breakdown.
    tp_sev_subquery = (
        "(SELECT COUNT(DISTINCT fm.vuln_id) FROM scan_findings sf "
        "JOIN finding_matches fm ON fm.finding_id = sf.id "
        "JOIN vulnerabilities v ON v.id = fm.vuln_id "
        "WHERE sf.scan_id = scans.id AND v.invalidated_at_revision IS NULL "
        "AND lower(v.severity) = ?)"
    )
    base_query = f"""SELECT scans.*, apps.name as app_name, apps.version as app_version,
                  users.name as submitter_name,
                  apps.visibility as app_visibility, apps.team_id as app_team_id,
                  {tp_subquery} as tp_count,
                  (SELECT COUNT(*) FROM (
                       SELECT DISTINCT COALESCE(NULLIF(fp_group, ''), 'ungrouped:' || id) AS g
                       FROM scan_findings WHERE scan_id=scans.id AND is_false_positive=1
                   )) as fp_count,
                  (SELECT COUNT(*) FROM scan_findings sf WHERE sf.scan_id=scans.id
                       AND NOT EXISTS (SELECT 1 FROM finding_matches fm WHERE fm.finding_id = sf.id)
                       AND sf.is_false_positive=0 AND sf.is_ignored=0) as pending_count,
                  ((SELECT COUNT(*) FROM vulnerabilities WHERE app_id = scans.app_id AND invalidated_at_revision IS NULL)
                   - {tp_subquery}) as fn_count,
                  {tp_sev_subquery} as tp_critical,
                  {tp_sev_subquery} as tp_high,
                  {tp_sev_subquery} as tp_medium,
                  {tp_sev_subquery} as tp_low,
                  {tp_sev_subquery} as tp_info,
                  {sev_subquery} as sev_critical,
                  {sev_subquery} as sev_high,
                  {sev_subquery} as sev_medium,
                  {sev_subquery} as sev_low,
                  {sev_subquery} as sev_info
           FROM scans
           LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE {vis_clause}{extra_filters}"""

    # Severity subqueries each take one bound parameter, prepended to the
    # existing visibility + filter params. SELECT-clause placeholders bind in
    # order of appearance, so the TP split (which is listed first) binds first.
    SEVERITIES = ["critical", "high", "medium", "low", "info"]
    sev_params = SEVERITIES + SEVERITIES

    if latest:
        sql = f"""WITH base AS ({base_query}),
                  ranked AS (
                      SELECT *, ROW_NUMBER() OVER (
                          PARTITION BY scanner_name, app_id
                          ORDER BY scan_date DESC, created_at DESC
                      ) as rn FROM base
                  )
                  SELECT * FROM ranked WHERE rn = 1
                  ORDER BY created_at DESC"""
    else:
        sql = base_query + " ORDER BY scans.created_at DESC"

    # The base query's SELECT contains the severity subqueries (which use
    # placeholders), then the WHERE clause's visibility + extra-filter params.
    cursor = await db.execute(sql, sev_params + vis_params + extra_params)
    scans = await cursor.fetchall()
    if include_metrics:
        metrics = await scoring_service.score_many(db, scans)
        # `metrics` stays scalar-only: the grouped view averages every field in
        # it, so a nested value there would be meaningless to aggregate.
        detail_keys = {"tiers", "matched_vuln_ids", "missed_vuln_ids",
                       "credit_by_vuln", "credit_by_chain", "tp_by_severity"}
        scored = []
        for scan in scans:
            m = metrics[scan["id"]]
            # The scorer's tp supersedes the SQL one here (it also applies the
            # existed_since_revision rule), so its split has to supersede the
            # SQL columns too — otherwise the breakdown would no longer add up
            # to the tp_count shown next to it.
            split = {f"tp_{sev}": count for sev, count in m["tp_by_severity"].items()}
            scored.append(dict(
                scan,
                metrics={key: value for key, value in m.items() if key not in detail_keys},
                **split,
            ))
        scans = scored

    # Batch-fetch labels for all returned scans
    scan_labels_map: dict[int, list[dict]] = {}
    scan_ids = [s["id"] for s in scans]
    if scan_ids:
        placeholders = ",".join("?" * len(scan_ids))
        cursor = await db.execute(
            f"""SELECT sl.scan_id, l.id, l.name, l.color
                FROM scan_labels sl JOIN labels l ON sl.label_id = l.id
                WHERE sl.scan_id IN ({placeholders})
                ORDER BY l.name""",
            scan_ids,
        )
        for row in await cursor.fetchall():
            scan_labels_map.setdefault(row["scan_id"], []).append(
                {"id": row["id"], "name": row["name"], "color": row["color"]}
            )

    # All label names for filter dropdown
    cursor = await db.execute("SELECT DISTINCT name FROM labels ORDER BY name")
    all_labels = [row["name"] for row in await cursor.fetchall()]

    # Distinct scanner names (scoped to app if filtered)
    scanner_filter = " AND scans.app_id = ?" if app_id else ""
    scanner_params = vis_params + ([app_id] if app_id else [])
    cursor = await db.execute(
        f"""SELECT DISTINCT scans.scanner_name
           FROM scans LEFT JOIN apps ON scans.app_id=apps.id
           WHERE {vis_clause}{scanner_filter}
           ORDER BY scans.scanner_name""",
        scanner_params,
    )
    scanners = [row["scanner_name"] for row in await cursor.fetchall()]

    # Distinct apps for filter dropdown
    cursor = await db.execute(
        f"""SELECT DISTINCT apps.id, apps.name, apps.version
           FROM scans JOIN apps ON scans.app_id=apps.id
           WHERE apps.name IS NOT NULL AND {vis_clause}
           ORDER BY apps.name, apps.version""",
        vis_params,
    )
    apps_list = await cursor.fetchall()

    # User's teams for filter dropdown
    user_teams = []
    if user:
        cursor = await db.execute(
            """SELECT teams.id, teams.name FROM teams
               JOIN team_members ON team_members.team_id = teams.id
               WHERE team_members.user_id = ?
               ORDER BY teams.name""",
            (user["sub"],),
        )
        user_teams = await cursor.fetchall()

    team_ids = {team["id"] for team in user_teams}
    visible_scans = []
    for scan in scans:
        can_view_cost = bool(user and (
            user["role"] == "admin"
            or scan["submitted_by"] == user["sub"]
            or (scan["app_visibility"] == "team" and scan["app_team_id"] in team_ids)
        ))
        scan_out = _scan_with_cost_permission(scan, can_view_cost)
        scan_out.pop("app_visibility")
        scan_out.pop("app_team_id")
        visible_scans.append(scan_out)

    # Combined coverage replaces the old summed totals row, which added TP/FN
    # across scans and so double-counted every vuln two scans both found.
    # Only defined when every listed scan is for the same app: a different
    # version of an app is a different app id, so "one app" is exact, and
    # across apps there is no single catalog to be covered.
    coverage = None
    listed_apps = {s["app_id"] for s in visible_scans}
    if len(listed_apps) == 1:
        coverage = await _coverage(db, next(iter(listed_apps)), [s["id"] for s in visible_scans])

    return {
        "scans": visible_scans,
        "coverage": coverage,
        "app": app,
        "scan_labels_map": scan_labels_map,
        "scanners": scanners,
        "apps_list": apps_list,
        "all_labels": all_labels,
        "user_teams": user_teams,
    }


async def _coverage(db, app_id: int, scan_ids: list[int]) -> dict:
    """What the listed scans found between them: distinct catalog vulns that
    at least one of them matched, and the ones none of them did.

    Scored against the app's current catalog -- the same scope as the list's
    own tp_count (``invalidated_at_revision IS NULL``), so this row and the
    rows above it never disagree about what counts. One query, not per-scan
    ids shipped to the client.
    """
    cursor = await db.execute(
        "SELECT id, vuln_id, title, severity FROM vulnerabilities "
        "WHERE app_id = ? AND invalidated_at_revision IS NULL "
        "ORDER BY vuln_id",
        (app_id,),
    )
    catalog = [dict(r) for r in await cursor.fetchall()]

    placeholders = ",".join("?" * len(scan_ids))
    cursor = await db.execute(
        f"SELECT DISTINCT fm.vuln_id FROM scan_findings sf "
        f"JOIN finding_matches fm ON fm.finding_id = sf.id "
        f"WHERE sf.scan_id IN ({placeholders}) AND fm.vuln_id IS NOT NULL",
        scan_ids,
    )
    found_ids = {r["vuln_id"] for r in await cursor.fetchall()}

    found = [v for v in catalog if v["id"] in found_ids]
    by_severity = {sev: 0 for sev in scoring.SEVERITY_WEIGHTS}
    for v in found:
        sev = (v["severity"] or "").lower()
        by_severity[sev if sev in by_severity else "info"] += 1
    return {
        "app_id": app_id,
        "scan_count": len(scan_ids),
        "found": len(found),
        "total": len(catalog),
        "found_by_severity": by_severity,
        "missed": [
            {"id": v["id"], "vuln_id": v["vuln_id"], "title": v["title"], "severity": v["severity"]}
            for v in catalog if v["id"] not in found_ids
        ],
    }


async def get_scan(db, user, scan_id: int) -> dict:
    """Get full scan detail with metrics, findings, labels, permissions."""
    cursor = await db.execute(
        "SELECT scans.*, users.name as submitter_name "
        "FROM scans LEFT JOIN users ON scans.submitted_by=users.id "
        "WHERE scans.id = ?",
        (scan_id,),
    )
    scan = await cursor.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (scan["app_id"],))
    app = await cursor.fetchone()

    # Visibility check — collapse "not authorized" into "not found" so the
    # response cannot be used to enumerate the existence of private scans
    # (vuln-0005, vuln-0008).
    if not user:
        if not (scan["is_public"] and app and app["visibility"] == "public"):
            raise ValueError("Scan not found")
    elif user["role"] != "admin":
        can_see = (
            (scan["is_public"] and app and app["visibility"] == "public")
            or scan["submitted_by"] == user["sub"]
            or (app and app["visibility"] == "team" and app["team_id"]
                and await get_team_role(db, user["sub"], app["team_id"]) is not None)
        )
        if not can_see:
            raise ValueError("Scan not found")

    # Live "current" view: the app's latest ground-truth revision. The as-run
    # number (at the scan's own corpus_revision) lives in the scorings rows
    # returned below, so the drift between the two is always visible.
    revision = await scoring_service.latest_revision(db, scan["app_id"])
    scored, missed_vulns = await _live_metrics(db, scan, revision)
    findings = scored["findings"]
    known_vulns = scored["vulns"]
    metrics = scored["metrics"]
    chains = scored["chains"]

    # Finding counts per matched vuln (for duplicate indicator)
    vuln_finding_counts = dict(
        Counter(vid for f in findings for vid in f["matched_vuln_ids"])
    )

    # Finding descriptions per matched vuln (for tooltips)
    vuln_finding_details: dict[int, list[str]] = {}
    for f in findings:
        lbl = f["vuln_type"] or ""
        loc = f["url"] or f["filename"] or ""
        if loc:
            lbl = f"{lbl}: {loc}"
        for vid in f["matched_vuln_ids"]:
            vuln_finding_details.setdefault(vid, []).append(lbl)

    # Edit / cost permissions
    can_edit = False
    can_view_cost = False
    if user:
        if user["role"] == "admin":
            can_edit = True
            can_view_cost = True
        elif scan["submitted_by"] == user["sub"]:
            can_edit = True
            can_view_cost = True
        elif app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            if team_role in ("admin", "contributor"):
                can_edit = True
            if team_role is not None:
                can_view_cost = True

    # Labels for this scan
    cursor = await db.execute(
        """SELECT l.id, l.name, l.color FROM labels l
           JOIN scan_labels sl ON sl.label_id = l.id
           WHERE sl.scan_id = ? ORDER BY l.name""",
        (scan_id,),
    )
    labels = [dict(row) for row in await cursor.fetchall()]

    # All labels for autocomplete
    cursor = await db.execute("SELECT id, name, color FROM labels ORDER BY name")
    all_labels = [dict(row) for row in await cursor.fetchall()]

    scan_out = _scan_with_cost_permission(scan, can_view_cost)

    return {
        "scan": scan_out,
        "app": app,
        "metrics": scoring.json_metrics(metrics),
        "findings": findings,
        "missed_vulns": missed_vulns,
        "known_vulns": known_vulns,
        "chains": chains,
        "labels": labels,
        "all_labels": all_labels,
        "can_edit": can_edit,
        "can_view_cost": can_view_cost,
        "vuln_finding_counts": vuln_finding_counts,
        "vuln_finding_details": vuln_finding_details,
        # Measurement context. Every rendered number is labelled with the
        # revision it was computed against.
        "revision": revision,
    }


# Who imported/mapped a scan and how it was run (migration 042). Text fields
# are stored as given (trimmed, capped); the integer ones must parse or are
# dropped. Anything else in a submission body is still ignored.
RUN_TEXT_FIELDS = (
    "imported_by", "importer_version", "importer_commit",
    "extractor_version", "extractor_prompt_sha256",
    "matcher_version", "matcher_prompt_sha256",
    "model", "model_version", "reasoning_effort", "harness_version", "run_group",
)
RUN_INT_FIELDS = ("token_budget", "seed", "trial_index")


def clean_run_details(body: dict) -> dict:
    out = {}
    for key in RUN_TEXT_FIELDS:
        value = body.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            out[key] = str(value).strip()[:200]
    for key in RUN_INT_FIELDS:
        try:
            if body.get(key) not in (None, ""):
                out[key] = int(body[key])
        except (TypeError, ValueError):
            pass
    return out


async def submit_scan(
    db, user,
    app_id: int,
    scanner_name: str,
    scan_date: str,
    is_public: int,
    notes: str | None,
    cost: float | None,
    tokens: int | None,
    duration: int | None,
    findings_data: list[dict],
    labels: list[str] | None = None,
    scanner_version: str | None = None,
    run_details: dict | None = None,
) -> int:
    """Create a scan, auto-match findings, apply labels. Returns scan_id.

    *run_details* is provenance and run configuration (``clean_run_details``);
    omitted keys stay NULL, which is what "imported by: unknown" means.
    """
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _check_scan_submit(db, user, app)

    # A scan can only be public when its parent app is public; otherwise the
    # is_public flag would expose a scan on a private/team app to anonymous
    # readers (vuln-0018).
    if is_public and app["visibility"] != "public":
        is_public = 0

    # The corpus revision this run is measured against ("as-run").
    await scoring_service.ensure_initial_revision(db, app_id, user)
    corpus_revision = await scoring_service.latest_revision(db, app_id)

    cursor = await db.execute(
        """INSERT INTO scans (app_id, scanner_name, scanner_version, scan_date, is_public,
                              notes, cost, tokens, duration, submitted_by, corpus_revision)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            app_id, scanner_name, scanner_version, scan_date, is_public,
            notes, cost, tokens, duration, user["sub"], corpus_revision,
        ),
    )
    scan_id = cursor.lastrowid

    details = clean_run_details(run_details or {})
    if details:
        cols = ", ".join(f"{k} = ?" for k in details)
        await db.execute(f"UPDATE scans SET {cols} WHERE id = ?", (*details.values(), scan_id))

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ?", (app_id,)
    )
    known_vulns = await cursor.fetchall()

    for f in findings_data:
        matched_vuln_id, is_false_positive = match_finding_algo(f, known_vulns)
        fp_group = (f.get("fp_group") or "").strip() or None
        cursor = await db.execute(
            """INSERT INTO scan_findings
               (scan_id, vuln_type, http_method, url, parameter, filename,
                is_false_positive, fp_group,
                title, severity, description, poc, remediation, code_location,
                reasoning, is_chain)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.get("vuln_type", ""),
                f.get("http_method", ""),
                f.get("url", ""),
                f.get("parameter", ""),
                f.get("filename", ""),
                is_false_positive,
                fp_group,
                f.get("title"),
                f.get("severity"),
                f.get("description"),
                f.get("poc"),
                f.get("remediation"),
                f.get("code_location"),
                f.get("reasoning"),
                # Whether the finding presents itself as a chain — the
                # importer decides from content, never from report layout.
                1 if f.get("is_chain") in (True, 1, "1", "true") else 0,
            ),
        )
        # The heuristic matcher proposes at most one vuln; the importer's LLM
        # corrections that follow submission are what add any further matches.
        if matched_vuln_id is not None:
            await finding_matches.replace(db, cursor.lastrowid, [matched_vuln_id], [])

    # Apply labels. Anyone with scan-write access can attach an existing
    # label; creating a brand-new label name is further restricted to
    # global admins and team contributors/admins on the app's own team
    # (vuln-0021 originally made this admin-only, but a team contributor
    # who can already submit scans for this app shouldn't need a global
    # admin just to coin a new label name). Unknown names are silently
    # skipped so well-behaved CI integrations don't blow up.
    if labels:
        can_create_labels = user["role"] == "admin"
        if not can_create_labels and app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            can_create_labels = team_role in ("admin", "contributor")
        for label_name in labels:
            label_name = label_name.strip()
            if not label_name:
                continue
            cursor = await db.execute(
                "SELECT id FROM labels WHERE name = ?", (label_name,)
            )
            label_row = await cursor.fetchone()
            if not label_row:
                if not can_create_labels:
                    continue
                await db.execute(
                    "INSERT INTO labels (name, color) VALUES (?, ?)",
                    (label_name, "#f97316"),
                )
                cursor = await db.execute(
                    "SELECT id FROM labels WHERE name = ?", (label_name,)
                )
                label_row = await cursor.fetchone()
            await db.execute(
                "INSERT OR IGNORE INTO scan_labels (scan_id, label_id) VALUES (?, ?)",
                (scan_id, label_row["id"]),
            )

    await db.commit()

    return scan_id


async def delete_scan(db, user, scan_id: int) -> None:
    """Delete a scan and its findings, label associations, and state blob."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    state_file = _state_path(scan_id)
    if state_file.exists():
        try:
            state_file.unlink()
        except OSError:
            pass

    await db.execute("DELETE FROM scan_labels WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
    await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await db.commit()


async def update_scan(db, user, scan_id: int, updates: dict) -> dict:
    """Update scan metadata (scanner_name, scan_date, notes, is_public, ...)."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    allowed = {
        "scanner_name", "scanner_version", "scan_date", "notes",
        "cost", "tokens", "duration", "is_public",
    }
    clean = {k: v for k, v in updates.items() if k in allowed and v is not None}

    # is_public must respect the parent app's visibility (vuln-0018).
    if "is_public" in clean:
        new_pub = 1 if clean["is_public"] in (True, 1, "1", "true") else 0
        if new_pub and app["visibility"] != "public":
            raise ValueError("Cannot publish a scan on a non-public app")
        clean["is_public"] = new_pub

    if not clean:
        return dict(scan)

    set_clause = ", ".join(f"{k}=?" for k in clean)
    values = list(clean.values()) + [scan_id]
    await db.execute(f"UPDATE scans SET {set_clause} WHERE id=?", values)
    await db.commit()

    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    return dict(await cursor.fetchone())


async def match_finding(db, user, scan_id: int, finding_id: int, vuln_ids, chain_ids) -> dict:
    """Set a finding's matches to exactly *vuln_ids* plus *chain_ids*.

    A finding can demonstrate several things at once (migration 040): a chain
    plus the members it walks through, or a single file read that proves both
    a traversal bug and a hardcoded secret. Passing two empty lists clears the
    finding back to pending.

    Matching to a chain is first-class evidence the chain was demonstrated
    (see app/scoring.py::compute_metrics) — the scanner's own report contained
    one finding narrating >=2 members combining, as opposed to two unrelated
    findings that each match one member. Crediting those members alongside it
    is a separate assertion the caller makes explicitly; it is never inferred
    from the chain match here.

    Every supplied vuln/chain must belong to the same app as the scan —
    otherwise the row would reference ground truth the caller may not be
    allowed to read, leaking cross-tenant data (vuln-0004).

    Returns {ok, matched_vuln_ids, matched_chain_ids, is_false_positive}.
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    def _as_ids(values, label):
        out = []
        for v in values or []:
            try:
                out.append(int(v))
            except (TypeError, ValueError):
                raise ValueError(f"{label} must be integers")
        return list(dict.fromkeys(out))

    new_vuln_ids = _as_ids(vuln_ids, "vuln_ids")
    new_chain_ids = _as_ids(chain_ids, "chain_ids")

    cursor = await db.execute(
        "SELECT id, title, vuln_type FROM scan_findings WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    finding = await cursor.fetchone()
    if not finding:
        raise ValueError("Finding not found")
    finding_label = finding["title"] or finding["vuln_type"] or f"finding #{finding_id}"

    existing = (await finding_matches.load(db, [finding_id]))[finding_id]
    old_vuln_ids, old_chain_ids = existing["vuln_ids"], existing["chain_ids"]

    # Resolve every target, both to validate app ownership and to build
    # human-readable labels for the audit entry.
    labels: dict[tuple[str, int], str] = {}
    for vid in new_vuln_ids:
        cursor = await db.execute(
            "SELECT app_id, vuln_id FROM vulnerabilities WHERE id = ?", (vid,)
        )
        row = await cursor.fetchone()
        if not row or row["app_id"] != scan["app_id"]:
            raise ValueError("Vulnerability not found")
        labels[("vuln", vid)] = row["vuln_id"]
    for cid in new_chain_ids:
        cursor = await db.execute(
            "SELECT app_id, chain_id FROM chains WHERE id = ?", (cid,)
        )
        row = await cursor.fetchone()
        if not row or row["app_id"] != scan["app_id"]:
            raise ValueError("Chain not found")
        labels[("chain", cid)] = row["chain_id"]

    is_false_positive = 0
    await finding_matches.replace(db, finding_id, new_vuln_ids, new_chain_ids)
    # Matching (or clearing) a finding also lifts any "ignored" flag — the
    # states are mutually exclusive.
    await db.execute(
        "UPDATE scan_findings SET is_false_positive = ?, is_ignored = 0, fp_group = NULL, fp_impact_weight = NULL "
        "WHERE id = ? AND scan_id = ?",
        (is_false_positive, finding_id, scan_id),
    )
    # A reviewer mapping a finding to a chain is saying it IS a chain report,
    # which corrects the importer when it missed that. Unmapping never clears
    # the flag: it describes what the finding says, not what it matched.
    if new_chain_ids:
        await db.execute("UPDATE scan_findings SET is_chain = 1 WHERE id = ?", (finding_id,))

    if set(new_vuln_ids) != set(old_vuln_ids) or set(new_chain_ids) != set(old_chain_ids):
        new_labels = ", ".join(
            [labels[("vuln", v)] for v in new_vuln_ids]
            + [labels[("chain", c)] for c in new_chain_ids]
        )
        if not new_vuln_ids and not new_chain_ids:
            # Name what was dropped: the whole point of the entry is being able
            # to see later what the mapping used to be.
            old_labels = []
            for vid in old_vuln_ids:
                cursor = await db.execute(
                    "SELECT vuln_id FROM vulnerabilities WHERE id = ?", (vid,)
                )
                row = await cursor.fetchone()
                if row:
                    old_labels.append(row["vuln_id"])
            for cid in old_chain_ids:
                cursor = await db.execute(
                    "SELECT chain_id FROM chains WHERE id = ?", (cid,)
                )
                row = await cursor.fetchone()
                if row:
                    old_labels.append(row["chain_id"])
            message = f"{user['name']} removed the mapping of \"{finding_label}\""
            if old_labels:
                message += f" (was {', '.join(old_labels)})"
            action = "finding_unmatched"
        elif not old_vuln_ids and not old_chain_ids:
            message = f"{user['name']} matched \"{finding_label}\" to {new_labels}"
            action = "finding_matched"
        else:
            message = (
                f"{user['name']} changed the mapping of \"{finding_label}\" to {new_labels}"
            )
            action = "finding_matched"
        await audit_service.record_audit_event(
            db, entity_type="scan_finding", action=action, actor=user, message=message,
            entity_id=finding_id, scan_id=scan_id,
            details={
                "old_vuln_ids": old_vuln_ids, "new_vuln_ids": new_vuln_ids,
                "old_chain_ids": old_chain_ids, "new_chain_ids": new_chain_ids,
            },
        )

    await db.commit()

    return {
        "ok": True,
        "matched_vuln_ids": new_vuln_ids, "matched_chain_ids": new_chain_ids,
        # Scalars for older clients (a stale copy of the importer lives in the
        # ai-pentest-agent repo); they see the first of each.
        "matched_vuln_id": new_vuln_ids[0] if new_vuln_ids else None,
        "matched_chain_id": new_chain_ids[0] if new_chain_ids else None,
        "is_false_positive": is_false_positive,
    }


async def mark_finding_fp(db, user, scan_id: int, finding_id: int, fp_group=None,
                          fp_impact_weight=...) -> None:
    """Mark a finding as false positive (clears any match/ignore).

    *fp_group* clusters findings that describe the SAME non-issue, so precision
    counts one FP rather than three. Ungrouped FPs count individually.
    Reviewer penalties are independent of reported severity. Omission preserves
    an existing penalty; None resets it to unreviewed (27 conservative points).
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT title, vuln_type, fp_impact_weight FROM scan_findings WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    finding = await cursor.fetchone()
    if not finding:
        raise ValueError("Finding not found")
    finding_label = finding["title"] or finding["vuln_type"] or f"finding #{finding_id}"

    if fp_impact_weight is ...:
        fp_impact_weight = finding["fp_impact_weight"]
    elif fp_impact_weight is not None and (
        type(fp_impact_weight) is not int or fp_impact_weight not in scoring.WEIGHT_SCALE
    ):
        raise ValueError("fp_impact_weight must be null or one of 1, 3, 9, 27")
    group = (fp_group or "").strip() or None
    await finding_matches.clear(db, finding_id)
    await db.execute(
        "UPDATE scan_findings SET is_false_positive = 1, is_ignored = 0, fp_group = ?, fp_impact_weight = ? WHERE id = ? AND scan_id = ?",
        (group, fp_impact_weight, finding_id, scan_id),
    )
    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action="finding_marked_fp", actor=user,
        message=f"{user['name']} marked \"{finding_label}\" as a false positive"
                f" (impact penalty: {fp_impact_weight if fp_impact_weight is not None else 'unreviewed, 27 conservative'} points)",
        entity_id=finding_id, scan_id=scan_id,
        details={"fp_group": group, "fp_impact_weight": fp_impact_weight,
                 "previous_fp_impact_weight": finding["fp_impact_weight"]},
    )
    await db.commit()


async def confirm_chain_credit(db, user, scan_id: int, chain_pk: int, notes=None) -> dict:
    """Explicitly confirm that *scan_id* demonstrates *chain_pk* end to end.

    Matching every member of a chain is necessary but never sufficient on its
    own (see migration 038) — this is the only thing that grants credit, and
    it exists precisely because inferring credit from matching alone was
    shown to credit chains whose own finding text explicitly denied any
    connection between the members. Call this only after reading the scan's
    actual finding text for every member and confirming it narrates the
    pivot, not just that both bugs happen to appear in the report.

    Raises ``ValueError`` if scan/chain not found, or the chain's members
    aren't all matched by this scan (confirming an impossible chain is
    never meaningful). Raises ``PermissionError`` if access is denied.
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT * FROM chains WHERE id = ? AND app_id = ?", (chain_pk, scan["app_id"])
    )
    chain = await cursor.fetchone()
    if not chain:
        raise ValueError("Chain not found")

    cursor = await db.execute(
        "SELECT vuln_id FROM chain_members WHERE chain_pk = ?", (chain_pk,)
    )
    member_ids = [row["vuln_id"] for row in await cursor.fetchall()]
    matched_ids = await finding_matches.matched_vuln_ids_for_scan(db, scan_id)
    if not member_ids or not all(vid in matched_ids for vid in member_ids):
        raise ValueError(
            "Not every member of this chain is matched by this scan — nothing to confirm"
        )

    await db.execute(
        """INSERT INTO scan_chain_credits (scan_id, chain_pk, credited_by, notes)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(scan_id, chain_pk) DO UPDATE SET
             credited_by = excluded.credited_by, notes = excluded.notes,
             credited_at = datetime('now')""",
        (scan_id, chain_pk, user["sub"], notes),
    )
    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action="chain_credit_confirmed", actor=user,
        message=f"{user['name']} confirmed {chain['chain_id']} (\"{chain['title']}\") "
                f"is demonstrated by this scan",
        scan_id=scan_id, details={"chain_pk": chain_pk},
    )
    await db.commit()
    return {"ok": True, "chain_pk": chain_pk, "credited": True}


async def revoke_chain_credit(db, user, scan_id: int, chain_pk: int) -> dict:
    """Undo a prior :func:`confirm_chain_credit` — the chain reverts to 0 credit.

    Raises ``ValueError`` if scan not found. Silently succeeds if the chain
    was never confirmed. Raises ``PermissionError`` if access is denied.
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT chain_id, title FROM chains WHERE id = ?", (chain_pk,)
    )
    chain = await cursor.fetchone()

    await db.execute(
        "DELETE FROM scan_chain_credits WHERE scan_id = ? AND chain_pk = ?",
        (scan_id, chain_pk),
    )
    if chain:
        await audit_service.record_audit_event(
            db, entity_type="scan_finding", action="chain_credit_revoked", actor=user,
            message=f"{user['name']} revoked {chain['chain_id']} (\"{chain['title']}\") "
                    f"credit for this scan",
            scan_id=scan_id, details={"chain_pk": chain_pk},
        )
    await db.commit()
    return {"ok": True, "chain_pk": chain_pk, "credited": False}


async def set_finding_ignored(db, user, scan_id: int, finding_id: int, ignored: bool) -> None:
    """Set/clear a finding's "ignored" state. Ignoring clears any match/FP so the
    states stay mutually exclusive; clearing returns the finding to Pending."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    cursor = await db.execute(
        "SELECT title, vuln_type, is_false_positive FROM scan_findings WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    finding = await cursor.fetchone()
    if not finding:
        raise ValueError("Finding not found")
    finding_label = finding["title"] or finding["vuln_type"] or f"finding #{finding_id}"

    if ignored:
        # Ignoring is reachable from any state, so it can discard a mapping or
        # an FP mark. Name what was thrown away -- "marked as ignored" alone
        # would leave no trace of the matches this dropped.
        existing = (await finding_matches.load(db, [finding_id])).get(
            finding_id, {"vuln_ids": [], "chain_ids": []}
        )
        dropped = len(existing["vuln_ids"]) + len(existing["chain_ids"])
        was_fp = bool(finding["is_false_positive"])

        await finding_matches.clear(db, finding_id)
        await db.execute(
            "UPDATE scan_findings SET is_ignored = 1, is_false_positive = 0, fp_group = NULL, fp_impact_weight = NULL WHERE id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        message = f"{user['name']} marked \"{finding_label}\" as ignored"
        if dropped:
            message += f" (dropped {dropped} existing match{'es' if dropped != 1 else ''})"
        elif was_fp:
            message += " (was marked false positive)"
        action = "finding_marked_ignored"
    else:
        await db.execute(
            "UPDATE scan_findings SET is_ignored = 0 WHERE id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        message = f"{user['name']} un-ignored \"{finding_label}\" (returned to Pending)"
        action = "finding_unignored"

    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action=action, actor=user, message=message,
        entity_id=finding_id, scan_id=scan_id,
    )
    await db.commit()


_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


async def _next_disc_slug(db, app_id: int) -> str:
    """Return the next DISC-NNN slug for the app (zero-padded, starts at 001)."""
    cursor = await db.execute(
        "SELECT vuln_id FROM vulnerabilities WHERE app_id = ? AND vuln_id LIKE 'DISC-%'",
        (app_id,),
    )
    max_n = 0
    for row in await cursor.fetchall():
        suffix = row["vuln_id"][5:]
        if suffix.isdigit():
            n = int(suffix)
            if n > max_n:
                max_n = n
    return f"DISC-{max_n + 1:03d}"


async def promote_finding(
    db, user, scan_id: int, finding_id: int, overrides: dict | None = None,
) -> dict:
    """Create a vuln on the scan's app from a pending finding's details, then
    link the finding to the new vuln.

    *overrides* may supply or replace any of: vuln_id, title, severity, vuln_type,
    description, poc, remediation, code_location, http_method, url, parameter,
    filename, impact_weight, difficulty_tier. Anything missing falls back to the
    finding's stored values; severity defaults to "medium" and vuln_id
    auto-generates as the next DISC-NNN.

    Promotion changes ground truth, so it always opens a new revision with
    reason ``new_prior_vuln``, and ``overrides["existed_since"]`` is REQUIRED:

      ``all_along``     — the flaw was in the app from revision 1. Every prior
                          scan legitimately takes the miss on re-score.
      ``this_revision`` — a code change introduced it. Prior scans untouched.

    That choice is the entire reason ``existed_since_revision`` and
    ``known_since_revision`` are separate fields, so it is never defaulted
    silently.

    Requires app-write (creating a vuln is an app-level action).

    Returns {ok, vuln, finding_id, revision}.
    """
    overrides = overrides or {}
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM scan_findings WHERE id = ? AND scan_id = ?",
        (finding_id, scan_id),
    )
    finding = await cursor.fetchone()
    if not finding:
        raise ValueError("Finding not found")

    def _pick(key: str, default=None):
        if key in overrides and overrides[key] not in (None, ""):
            return overrides[key]
        val = finding[key] if key in finding.keys() else None
        return val if val not in (None, "") else default

    existed_since_choice = (overrides.get("existed_since") or "").strip().lower()
    if existed_since_choice not in ("all_along", "this_revision"):
        raise ValueError(
            "existed_since must be 'all_along' (the flaw was always present — prior "
            "scans take the miss) or 'this_revision' (a code change introduced it)"
        )

    title = _pick("title") or _pick("vuln_type") or "Untitled finding"
    severity = (_pick("severity") or "medium").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    # Scoring fields. Weight defaults from severity (always present and
    # validated) rather than rejecting the promotion; the tier defaults to
    # commodity and both are meant to be corrected by hand afterwards.
    impact_weight = scoring.validate_weight(overrides.get("impact_weight"))
    if impact_weight is None:
        impact_weight = scoring.weight_from_severity(severity)
    difficulty_tier = scoring.validate_tier(overrides.get("difficulty_tier")) or scoring.DEFAULT_TIER

    vuln_id_slug = overrides.get("vuln_id") or await _next_disc_slug(db, app["id"])

    new_revision = await scoring_service.create_revision(
        db, app["id"], "new_prior_vuln",
        notes=f"Promoted finding #{finding_id} from scan #{scan_id}: {title}",
        user=user,
    )
    existed_since = 1 if existed_since_choice == "all_along" else new_revision

    cursor = await db.execute(
        """INSERT INTO vulnerabilities
           (app_id, vuln_id, title, severity, vuln_type, http_method, url,
            parameter, filename, description, code_location, poc, remediation,
            created_by, impact_weight, difficulty_tier,
            existed_since_revision, known_since_revision)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            app["id"],
            vuln_id_slug,
            title,
            severity,
            _pick("vuln_type"),
            _pick("http_method"),
            _pick("url"),
            _pick("parameter"),
            _pick("filename"),
            _pick("description"),
            _pick("code_location"),
            _pick("poc"),
            _pick("remediation"),
            user["sub"],
            impact_weight,
            difficulty_tier,
            existed_since,
            new_revision,
        ),
    )
    new_vuln_id = cursor.lastrowid

    await finding_matches.replace(db, finding_id, [new_vuln_id], [])
    await db.execute(
        "UPDATE scan_findings SET is_false_positive = 0, is_ignored = 0, fp_group = NULL, fp_impact_weight = NULL WHERE id = ?",
        (finding_id,),
    )

    finding_label = finding["title"] or finding["vuln_type"] or f"finding #{finding_id}"
    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action="finding_promoted", actor=user,
        message=f"{user['name']} promoted \"{finding_label}\" to new vulnerability {vuln_id_slug}",
        entity_id=finding_id, scan_id=scan_id,
        details={"new_vuln_id": new_vuln_id},
    )
    await audit_service.record_audit_event(
        db, entity_type="vulnerability", action="vuln_created", actor=user,
        message=f"{user['name']} created vulnerability {vuln_id_slug}: \"{title}\" ({severity}) via promotion from scan #{scan_id}",
        entity_id=new_vuln_id, app_id=app["id"],
        details={"scan_id": scan_id, "finding_id": finding_id},
    )

    await db.commit()

    cursor = await db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (new_vuln_id,))
    vuln_row = await cursor.fetchone()

    return {
        "ok": True,
        "vuln": dict(vuln_row),
        "finding_id": finding_id,
        "revision": new_revision,
        "existed_since_revision": existed_since,
    }


async def promote_finding_to_chain(
    db, user, scan_id: int, finding_id: int, chain_data: dict,
) -> dict:
    """Register a chain the catalog is missing, from a finding that reports it.

    The counterpart of ``promote_finding`` for chain reports. Before it, a scan
    that demonstrated a real chain the catalog did not have could only mark it
    FP (charging the scanner for a true discovery), ignore it, or promote it as
    a single flat vuln with no members — scan 330 lost three chains that way.

    *chain_data* is what ``chains.create_chain`` takes: title, severity,
    member_vuln_ids (>= 2, existing vulns on this app, in step order),
    description, and optionally existed_since_revision (default 1 — a chain is
    made of flaws that were already there). A member the catalog lacks must be
    promoted as a vuln first; that keeps every member a flaw some scan
    actually showed, rather than inventing ground truth from a narrative.

    The finding keeps any vulns it already credits and gains the chain, and is
    flagged ``is_chain``. Returns {ok, chain, finding_id}.
    """
    from app.services import chains as chains_service

    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_app_write(db, user, app)

    cursor = await db.execute(
        "SELECT * FROM scan_findings WHERE id = ? AND scan_id = ?", (finding_id, scan_id)
    )
    finding = await cursor.fetchone()
    if not finding:
        raise ValueError("Finding not found")

    data = dict(chain_data or {})
    data.setdefault("title", finding["title"] or finding["vuln_type"] or "Untitled chain")
    data.setdefault("description", finding["description"])

    chain = await chains_service.create_chain(db, user, app["id"], data)

    existing = (await finding_matches.load(db, [finding_id]))[finding_id]
    await finding_matches.replace(
        db, finding_id, existing["vuln_ids"], existing["chain_ids"] + [chain["id"]]
    )
    await db.execute(
        "UPDATE scan_findings SET is_chain = 1, is_false_positive = 0, is_ignored = 0, "
        "fp_group = NULL, fp_impact_weight = NULL WHERE id = ?",
        (finding_id,),
    )

    finding_label = finding["title"] or finding["vuln_type"] or f"finding #{finding_id}"
    was = " (was marked false positive)" if finding["is_false_positive"] else \
          " (was ignored)" if finding["is_ignored"] else ""
    await audit_service.record_audit_event(
        db, entity_type="scan_finding", action="finding_promoted_chain", actor=user,
        message=f"{user['name']} promoted \"{finding_label}\" to new chain "
                f"{chain['chain_id']}{was}",
        entity_id=finding_id, scan_id=scan_id, details={"chain_pk": chain["id"]},
    )
    await db.commit()
    return {"ok": True, "chain": chain, "finding_id": finding_id}


async def rematch_scan(db, user, scan_id: int) -> dict:
    """Re-run auto-matching on all findings in a scan. Returns {updated}."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    # Only vulns in scope at the current revision are match candidates —
    # re-matching must never resurrect an invalidated vuln.
    revision = await scoring_service.latest_revision(db, scan["app_id"])
    known_vulns = await scoring_service.fetch_vulns_in_scope(db, scan["app_id"], revision)

    cursor = await db.execute(
        "SELECT * FROM scan_findings WHERE scan_id = ?", (scan_id,)
    )
    findings = await finding_matches.attach(db, await cursor.fetchall())

    updated = 0
    for f in findings:
        # A manually-ignored finding is a deliberate decision — never auto-rematch it.
        if f["is_ignored"]:
            continue
        finding_dict = {
            "vuln_type": f["vuln_type"],
            "http_method": f["http_method"],
            "url": f["url"],
            "parameter": f["parameter"],
            "filename": f["filename"],
            "title": f["title"],
        }
        matched_vuln_id, is_false_positive = match_finding_algo(finding_dict, known_vulns)

        old_vuln_ids = f["matched_vuln_ids"]
        old_chain_ids = f["matched_chain_ids"]
        new_vuln_ids = [matched_vuln_id] if matched_vuln_id is not None else []
        # The heuristic only ever proposes one vuln and knows nothing about
        # chains, so it must not flatten a richer hand-made or LLM-made match
        # set back down to its own single guess.
        would_lose_matches = len(old_vuln_ids) > 1 or bool(old_chain_ids)
        if not would_lose_matches and (
            set(new_vuln_ids) != set(old_vuln_ids)
            or is_false_positive != f["is_false_positive"]
        ):
            await finding_matches.replace(db, f["id"], new_vuln_ids, [])
            await db.execute(
                "UPDATE scan_findings SET is_false_positive = ?, fp_group = NULL, fp_impact_weight = NULL WHERE id = ?",
                (is_false_positive, f["id"]),
            )
            updated += 1

    if updated:
        await audit_service.record_audit_event(
            db, entity_type="scan_finding", action="scan_rematched", actor=user,
            message=f"{user['name']} re-ran auto-matching on this scan — {updated} finding(s) changed",
            scan_id=scan_id,
            details={"updated": updated},
        )

    await db.commit()
    return {"updated": updated}


async def list_scan_history(db, user, scan_id: int) -> list[dict]:
    """Audit-log entries for this scan's findings, most recent first.

    Gated on the same write-access check as editing the scan — this app has
    no account-level contributor/viewer role today (see
    tasks/audit-log-plan.md SS0), so "contributor and admin can see it, viewer
    and user can't" is exactly what per-resource write access already means.
    """
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)
    return await audit_service.list_audit_events(db, scan_id=scan_id)


async def compare_scans(db, user, app_id: int, scan_ids: list[int]) -> dict:
    """Build comparison data for multiple scans on an app.

    Returns {app, available_scans, scanners, matrix, fp_matrix, known_vuln_count, can_edit}.
    """
    from app.visibility import app_visibility_filter
    vis_clause, vis_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"SELECT * FROM apps WHERE id = ? AND {vis_clause}",
        [app_id] + vis_params,
    )
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    # Edit permissions
    can_edit = False
    if user:
        if user["role"] == "admin":
            can_edit = True
        elif app["visibility"] != "public" and app["created_by"] == user["sub"]:
            can_edit = True
        elif app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            if team_role in ("admin", "contributor"):
                can_edit = True

    # Available scans for selector
    vis_clause, vis_params = scan_visibility_filter(user)
    cursor = await db.execute(
        f"""SELECT scans.*, users.name as submitter_name
           FROM scans LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE scans.app_id=? AND {vis_clause}
           ORDER BY scans.created_at DESC""",
        [app_id] + vis_params,
    )
    available_scans = await cursor.fetchall()

    # If no scan IDs, return just the selector data
    if not scan_ids:
        return {
            "app": app,
            "available_scans": available_scans,
            "scanners": [],
            "matrix": [],
            "fp_matrix": [],
            "known_vuln_count": 0,
            "can_edit": can_edit,
        }

    # Compare at ONE revision — the app's latest — so every column shares a
    # denominator. Mixing revisions silently compares against different ground
    # truth, which is the whole defect this axis exists to fix.
    revision = await scoring_service.latest_revision(db, app_id)
    known_vulns = await scoring_service.fetch_vulns_in_scope(db, app_id, revision)
    chains = await scoring_service.fetch_chains_in_scope(db, app_id, revision)

    # Build per-scanner comparison data
    scanners = []
    for sid in scan_ids:
        cursor = await db.execute(
            "SELECT * FROM scans WHERE id = ? AND app_id = ?", (sid, app_id)
        )
        scan = await cursor.fetchone()
        if not scan:
            continue

        scored, _missed = await _live_metrics(db, scan, revision)
        findings = scored["findings"]
        metrics = scored["metrics"]
        matched_ids = metrics["matched_vuln_ids"]

        cursor = await db.execute(
            """SELECT l.id, l.name, l.color FROM labels l
               JOIN scan_labels sl ON sl.label_id = l.id
               WHERE sl.scan_id = ? ORDER BY l.name""",
            (sid,),
        )
        scan_labels = [dict(row) for row in await cursor.fetchall()]

        fp_findings = [dict(f) for f in findings if f["is_false_positive"] == 1]

        # First reported severity per matched vuln (for the client-side
        # severity-accuracy recompute under a severity filter — mirrors
        # scoring.compute_metrics' reported_by_vuln, one value is enough here
        # since the UI only needs match/mismatch, not the full set).
        severity_by_vuln: dict = {}
        for f in findings:
            f_sev = (f["severity"] or "").strip().lower()
            if not f_sev:
                continue
            for vid in f["matched_vuln_ids"]:
                if vid in matched_ids and vid not in severity_by_vuln:
                    severity_by_vuln[vid] = f_sev

        # Short date: omit year if current year
        scan_date = scan["scan_date"]
        try:
            dt = datetime.strptime(scan_date, "%Y-%m-%d")
        except (ValueError, TypeError):
            try:
                dt = datetime.strptime(scan_date[:19], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                dt = None
        if dt:
            has_time = dt.hour or dt.minute
            if dt.year == datetime.now().year:
                short_date = dt.strftime("%b %d %H:%M") if has_time else dt.strftime("%b %d")
            else:
                short_date = dt.strftime("%b %d, %Y %H:%M") if has_time else dt.strftime("%b %d, %Y")
        else:
            short_date = scan_date

        scanners.append({
            "scan": scan,
            "short_date": short_date,
            "labels": scan_labels,
            "metrics": scoring.json_metrics(metrics),
            "matched_vuln_ids": matched_ids,
            "credit_by_vuln": metrics["credit_by_vuln"],
            # Which vulns this scan can be judged on: a flaw introduced after
            # the run is not a miss for it.
            "scope_vuln_ids": {v["id"] for v in scored["vulns"]},
            "fp_findings": fp_findings,
            "severity_by_vuln": severity_by_vuln,
        })

    # Sort by scan date ascending (oldest first)
    scanners.sort(key=lambda s: (s["scan"]["scan_date"] or "", s["scan"]["id"]))

    # Detection matrix. `credits` is 0/1 per scan (1 = matched); `applicable`
    # is false where the vuln postdates the run, so the cell reads "not
    # applicable" rather than a miss the scanner never had a chance at.
    matrix = []
    for v in known_vulns:
        row = {
            "vuln": v,
            "detections": [v["id"] in s["matched_vuln_ids"] for s in scanners],
            "credits": [s["credit_by_vuln"].get(v["id"], 0.0) for s in scanners],
            "applicable": [v["id"] in s["scope_vuln_ids"] for s in scanners],
            # Reported severity of the matched finding, per scanner — None
            # where not detected or the finding didn't report one.
            "severity_reported": [s["severity_by_vuln"].get(v["id"]) for s in scanners],
        }
        row["found_by"] = sum(row["detections"])
        row["applicable_count"] = sum(row["applicable"])
        matrix.append(row)

    # FP matrix
    fp_keys: dict[tuple, dict] = {}
    for i, s in enumerate(scanners):
        for fp in s["fp_findings"]:
            url_val = (fp.get("url") or "").strip()
            filename_val = (fp.get("filename") or "").strip()
            key = (
                (fp.get("vuln_type") or "").lower(),
                (fp.get("http_method") or "").lower(),
                url_val.lower(),
                (fp.get("parameter") or "").lower(),
                filename_val.lower(),
            )
            if key not in fp_keys:
                location = url_val or filename_val or "-"
                fp_keys[key] = {
                    "vuln_type": fp.get("vuln_type", ""),
                    "http_method": fp.get("http_method", ""),
                    "url": url_val,
                    "parameter": fp.get("parameter", ""),
                    "filename": filename_val,
                    "location": location,
                    "flagged_by": [False] * len(scanners),
                }
            fp_keys[key]["flagged_by"][i] = True

    fp_matrix = list(fp_keys.values())
    for fp in fp_matrix:
        fp["flagged_count"] = sum(fp["flagged_by"])
    fp_matrix.sort(key=lambda x: -x["flagged_count"])

    for s in scanners:
        s.pop("credit_by_vuln", None)
        s.pop("scope_vuln_ids", None)
        s["matched_vuln_ids"] = sorted(s["matched_vuln_ids"])

    return {
        "app": app,
        "available_scans": available_scans,
        "scanners": scanners,
        "matrix": matrix,
        "fp_matrix": fp_matrix,
        "known_vuln_count": len(known_vulns),
        "chains": chains,
        "can_edit": can_edit,
        "revision": revision,
        "label": f"{app['name']}@rev{revision}",
        "guards": _reporting_guards(scanners, revision, matrix),
    }


# ---------------------------------------------------------------------------
# Reporting guards
# ---------------------------------------------------------------------------

def _reporting_guards(scanners: list, revision: int, matrix: list) -> dict:
    """Machine-readable warnings about the comparison the caller just asked for.

    Deliberately advisory, never blocking — hard-refusing an exploratory
    scan-vs-scan comparison would break the tool's day-to-day use, including
    looking at an old scan next to a new one, which is exactly how you notice
    ground truth has moved.
    """
    corpus_revisions = sorted({
        int(scoring.field(s["scan"], "corpus_revision", revision) or revision)
        for s in scanners
    })
    incomplete = [
        s["scan"]["id"] for s in scanners
        if not s["metrics"]["adjudication_complete"]
    ]
    # Differing revision STAMPS are not on their own worth telling anyone about:
    # what matters is whether any cell is actually out of scope, which depends on
    # each vuln's existed_since_revision, not on the stamps. An app whose vulns
    # all existed_since_revision=1 (the default — the flaw was always there, it
    # just got documented later) has every vuln in scope for every scan, so no
    # cell can read "n/a" no matter how far the stamps have drifted. Counting the
    # real out-of-scope cells keeps the warning from explaining a non-event.
    out_of_scope_cells = sum(
        1 for row in matrix for applicable in row["applicable"] if not applicable
    )

    return {
        "revision": revision,
        "corpus_revisions": corpus_revisions,
        "out_of_scope_cells": out_of_scope_cells,
        "adjudication_incomplete_scans": incomplete,
        # Precision is meaningless before full adjudication; show the bounds.
        "suppress_precision": bool(incomplete),
    }


async def get_available_scans(db, user, app_id: int) -> list:
    """Get all visible scans for an app (for the scan selector)."""
    from app.visibility import app_visibility_filter
    app_vis, app_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"SELECT id FROM apps WHERE id = ? AND {app_vis}", [app_id] + app_params
    )
    if not await cursor.fetchone():
        raise ValueError("App not found")

    vis_clause, vis_params = scan_visibility_filter(user)
    cursor = await db.execute(
        f"""SELECT scans.*, users.name as submitter_name
           FROM scans LEFT JOIN apps ON scans.app_id=apps.id
           LEFT JOIN users ON scans.submitted_by=users.id
           WHERE scans.app_id=? AND {vis_clause}
           ORDER BY scans.created_at DESC""",
        [app_id] + vis_params,
    )
    return await cursor.fetchall()


# ---------------------------------------------------------------------------
# Scan state (zip blob of the source directory used to produce the scan)
# ---------------------------------------------------------------------------

def _state_path(scan_id: int) -> Path:
    return Path(STATE_DIR) / f"{scan_id}.zip"


async def set_scan_state(db, user, scan_id: int, content: bytes, filename: str) -> dict:
    """Persist a zip of the source-of-truth directory used to produce this
    scan. Overwrites any existing state. Returns the new metadata."""
    if len(content) > MAX_STATE_SIZE:
        raise ValueError(f"State file too large ({len(content)} > {MAX_STATE_SIZE} bytes)")
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)

    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256(content).hexdigest()
    path = _state_path(scan_id)
    # Write to a sibling tmp first, then rename — atomic enough for our needs.
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)

    safe_name = (filename or f"scan-{scan_id}.zip").strip() or f"scan-{scan_id}.zip"
    await db.execute(
        "UPDATE scans SET state_filename=?, state_size=?, state_sha256=? WHERE id=?",
        (safe_name, len(content), sha, scan_id),
    )
    await db.commit()
    return {"filename": safe_name, "size": len(content), "sha256": sha}


async def get_scan_state(db, user, scan_id: int) -> tuple[Path, str, int, str]:
    """Return (on-disk path, filename, size, sha256). Raises ValueError if
    no state attached, PermissionError if user cannot view this scan."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_view(db, user, scan, app)
    if not scan["state_filename"]:
        raise ValueError("No state attached to this scan")
    path = _state_path(scan_id)
    if not path.exists():
        raise ValueError("State file is missing on disk")
    return path, scan["state_filename"], scan["state_size"], scan["state_sha256"]


async def delete_scan_state(db, user, scan_id: int) -> None:
    """Remove the state blob (used when deleting a scan or by an explicit
    delete request)."""
    scan, app = await _get_scan_and_app(db, scan_id)
    await _check_scan_write(db, user, scan, app)
    path = _state_path(scan_id)
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass
    await db.execute(
        "UPDATE scans SET state_filename=NULL, state_size=NULL, state_sha256=NULL WHERE id=?",
        (scan_id,),
    )
    await db.commit()

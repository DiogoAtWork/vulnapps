from __future__ import annotations

import re
from urllib.parse import urlparse

from app.dependencies import get_team_role
from app.visibility import app_visibility_filter
from app.services.vulns import MAX_VULNS_PER_APP
from app.services import chains as chains_service


_ALLOWED_URL_SCHEMES = ("http", "https")
SOURCE_UNSET = object()


def _validate_url(url: str | None) -> str | None:
    """Normalize and validate a user-supplied URL.

    Rejects schemes other than http/https — in particular ``javascript:``,
    ``data:``, ``vbscript:``, and ``file:`` URIs that would otherwise be
    rendered as anchor hrefs by the SPA and trigger stored XSS (vuln-0010).
    """
    if url is None:
        return None
    url = url.strip()
    if not url:
        return None
    scheme = urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise ValueError("URL must start with http:// or https://")
    return url


def _validate_source_repository(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Source repository must be an HTTP(S) URL")
    value = value.strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        valid = (
            parsed.scheme.lower() in _ALLOWED_URL_SCHEMES
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and "\\" not in value
            and not any(character.isspace() or ord(character) < 32 for character in value)
        )
        parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Source repository must be an HTTP(S) URL without credentials")
    return value


def _validate_source_commit(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Source commit must be a full 40- or 64-character hexadecimal SHA")
    value = value.strip().lower()
    if not value:
        return None
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise ValueError("Source commit must be a full 40- or 64-character hexadecimal SHA")
    return value


def _validate_source_directory(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or any(ord(character) < 32 for character in value):
        raise ValueError("Source directory must be a relative POSIX path without control characters")
    value = value.strip()
    if not value:
        return None
    if (value.startswith("/") or "\\" in value
            or ".." in value.split("/")):
        raise ValueError("Source directory must be a relative POSIX path without parent traversal")
    return "/".join(part for part in value.split("/") if part and part != ".") or None


# ---------------------------------------------------------------------------
# Helpers (private)
# ---------------------------------------------------------------------------

async def _get_tech_stack(db, app_id: int) -> list[str]:
    cursor = await db.execute(
        "SELECT name FROM app_technologies WHERE app_id = ? ORDER BY name",
        (app_id,),
    )
    return [row["name"] for row in await cursor.fetchall()]


async def _save_tech_stack(db, app_id: int, tech_string: str) -> None:
    await db.execute("DELETE FROM app_technologies WHERE app_id = ?", (app_id,))
    for name in (t.strip() for t in tech_string.split(",") if t.strip()):
        await db.execute(
            "INSERT OR IGNORE INTO app_technologies (app_id, name) VALUES (?, ?)",
            (app_id, name),
        )


def _check_app_write(user, app) -> bool:
    """Return True if *user* has write access to *app*.

    Rules (mirrored from ``require_app_write``):
    - Admin: always allowed
    - Public apps: admin only
    - Private apps: creator only
    - Team apps: creator (team role checked separately where db is available)
    """
    if not user:
        return False
    if user["role"] == "admin":
        return True
    if app["visibility"] == "public":
        return False
    if app["created_by"] == user["sub"]:
        return True
    return False


async def _check_app_write_full(db, user, app) -> bool:
    """Full write-permission check including async team role lookup."""
    if _check_app_write(user, app):
        return True
    if (
        user
        and app["visibility"] == "team"
        and app["team_id"]
    ):
        team_role = await get_team_role(db, user["sub"], app["team_id"])
        if team_role in ("admin", "contributor"):
            return True
    return False


async def _require_app_write(db, user, app) -> None:
    """Raise ``PermissionError`` when user lacks write access."""
    if not user:
        raise PermissionError("Authentication required")
    if not await _check_app_write_full(db, user, app):
        raise PermissionError("You don't have write access to this app")


def _validate_visibility(user, visibility, team_id):
    """Validate visibility/team_id combination. Raises PermissionError or ValueError."""
    if visibility not in ("public", "team", "private"):
        visibility = "private"
    if visibility == "public" and user["role"] != "admin":
        raise PermissionError("Only admins can create public apps")
    if visibility == "team" and not team_id:
        raise ValueError("Team required for team visibility")
    return visibility


async def _validate_team_access(db, user, team_id):
    """Raise PermissionError if user lacks contributor+ access to the team."""
    team_role = await get_team_role(db, user["sub"], team_id)
    if user["role"] != "admin" and team_role not in ("admin", "contributor"):
        raise PermissionError("Team contributor access required")


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

async def list_apps(db, user, q: str = "", filter: str = "") -> list:
    """Return apps visible to *user*, optionally filtered by *q* and *filter*.

    Each item is a dict with keys: app (row), tech (list[str]).
    The app row includes ``vuln_count``, ``scan_count``, and ``creator_name``.
    """
    vis_clause, vis_params = app_visibility_filter(user)
    extra_filters = ""
    extra_params: list = []

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

    if q:
        extra_filters += " AND apps.name LIKE ?"
        extra_params.append(f"%{q}%")

    query = f"""
        SELECT apps.*, users.name as creator_name, teams.name as team_name,
               (SELECT COUNT(*) FROM vulnerabilities WHERE app_id=apps.id) as vuln_count,
               (SELECT COUNT(*) FROM scans WHERE app_id=apps.id) as scan_count
        FROM apps
        LEFT JOIN users ON apps.created_by=users.id
        LEFT JOIN teams ON apps.team_id=teams.id
        WHERE {vis_clause}{extra_filters}
        ORDER BY apps.created_at DESC
    """
    cursor = await db.execute(query, vis_params + extra_params)
    apps = await cursor.fetchall()

    result = []
    for app in apps:
        tech = await _get_tech_stack(db, app["id"])
        result.append({"app": app, "tech": tech})
    return result


async def get_app(db, user, app_id: int) -> dict:
    """Return full app detail visible to *user*.

    Returns a dict with keys:
        app, vulns, tech_stack, scan_count,
        severity_counts, can_edit, can_submit_scan
    Raises ``ValueError`` if not found / not visible.
    """
    vis_clause, vis_params = app_visibility_filter(user)
    cursor = await db.execute(
        f"""SELECT apps.*, users.name as creator_name
            FROM apps LEFT JOIN users ON apps.created_by=users.id
            WHERE apps.id = ? AND {vis_clause}""",
        [app_id] + vis_params,
    )
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    # Counts come from SQL aggregates, never from len(vulns): the returned
    # list is capped (below) so the response can't balloon into a multi-MB
    # payload — a single flooded app once made this a 14 MB / OOM response.
    # Counts stay accurate even if the row list is truncated.
    cursor = await db.execute(
        "SELECT severity, COUNT(*) AS c FROM vulnerabilities WHERE app_id = ? GROUP BY severity",
        (app_id,),
    )
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vuln_count = 0
    for row in await cursor.fetchall():
        severity_counts[row["severity"]] = row["c"]
        vuln_count += row["c"]

    cursor = await db.execute(
        "SELECT * FROM vulnerabilities WHERE app_id = ? ORDER BY severity, title LIMIT ?",
        (app_id, MAX_VULNS_PER_APP),
    )
    vulns = await cursor.fetchall()
    vulns_truncated = vuln_count > len(vulns)

    cursor = await db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE app_id = ?", (app_id,)
    )
    scan_count = (await cursor.fetchone())["count"]

    tech_stack = await _get_tech_stack(db, app_id)
    chains = await chains_service.list_chains(db, user, app_id)

    # Permissions
    can_edit = False
    can_submit_scan = False
    if user:
        if user["role"] == "admin":
            can_edit = True
            can_submit_scan = True
        elif app["visibility"] == "public":
            can_edit = False
            can_submit_scan = False
        elif app["created_by"] == user["sub"]:
            can_edit = True
            can_submit_scan = True
        elif app["visibility"] == "team" and app["team_id"]:
            team_role = await get_team_role(db, user["sub"], app["team_id"])
            if team_role in ("admin", "contributor"):
                can_edit = True
                can_submit_scan = True

    return {
        "app": app,
        "vulns": vulns,
        "vuln_count": vuln_count,
        "vulns_truncated": vulns_truncated,
        "chains": chains,
        "tech_stack": tech_stack,
        "scan_count": scan_count,
        "severity_counts": severity_counts,
        "can_edit": can_edit,
        "can_submit_scan": can_submit_scan,
    }


async def create_app(
    db,
    user,
    name: str,
    version: str,
    description: str | None,
    url: str | None,
    visibility: str,
    team_id: int | None,
    tech_stack: str,
    clone_from: int | None = None,
    source_repository=SOURCE_UNSET,
    source_commit=SOURCE_UNSET,
    source_directory=SOURCE_UNSET,
) -> dict:
    """Create a new app and return its row as a dict.

    *tech_stack* is a comma-separated string.
    If *clone_from* is given, vulnerabilities are copied from that app
    (provided the user has read access to it). Omitted source fields inherit
    from that app; explicit ``None`` clears them.

    Raises ``PermissionError`` for visibility violations.
    Raises ``ValueError`` for invalid inputs (e.g. team visibility without team).
    """
    if not user:
        raise PermissionError("Authentication required")

    url = _validate_url(url)
    visibility = _validate_visibility(user, visibility, team_id)
    if visibility == "team":
        await _validate_team_access(db, user, team_id)

    source_app = None
    if clone_from:
        vis_clause, vis_params = app_visibility_filter(user)
        cursor = await db.execute(
            f"SELECT * FROM apps WHERE id = ? AND {vis_clause}",
            [clone_from] + vis_params,
        )
        source_app = await cursor.fetchone()
    if source_repository is SOURCE_UNSET:
        source_repository = source_app["source_repository"] if source_app else None
    if source_commit is SOURCE_UNSET:
        source_commit = source_app["source_commit"] if source_app else None
    if source_directory is SOURCE_UNSET:
        source_directory = source_app["source_directory"] if source_app else None
    source_repository = _validate_source_repository(source_repository)
    source_commit = _validate_source_commit(source_commit)
    source_directory = _validate_source_directory(source_directory)

    cursor = await db.execute(
        """INSERT INTO apps (name, version, description, url, created_by,
           visibility, team_id, source_repository, source_commit, source_directory)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, version, description, url, user["sub"], visibility, team_id,
         source_repository, source_commit, source_directory),
    )
    app_id = cursor.lastrowid
    await _save_tech_stack(db, app_id, tech_stack)

    # Clone vulnerabilities (and any chains over them) from source app. A
    # clone is meant to be "the current reviewed state, on a new version" --
    # it must carry forward impact_weight/difficulty_tier/weight_verified
    # (the actual curation work) and chains (their own ground-truth entity,
    # contributing their own weight), not just the raw vuln text. Revision
    # bookkeeping (existed_since/known_since/invalidated_at) is specific to
    # the SOURCE app's revision timeline and meaningless in the new app's,
    # so those reset to a fresh revision 1 rather than being copied; an
    # invalidated (retired) source vuln is skipped rather than cloned back in.
    if source_app:
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE app_id = ? AND invalidated_at_revision IS NULL",
            (clone_from,),
        )
        source_vulns = await cursor.fetchall()
        vuln_id_map: dict[int, int] = {}
        for v in source_vulns:
            cursor = await db.execute(
                """INSERT INTO vulnerabilities
                   (app_id, vuln_id, title, severity, vuln_type, http_method,
                    url, parameter, filename, line_number, description,
                    code_location, poc, remediation, created_by,
                    impact_weight, difficulty_tier, weight_verified,
                    existed_since_revision, known_since_revision)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)""",
                (
                    app_id,
                    v["vuln_id"],
                    v["title"],
                    v["severity"],
                    v["vuln_type"],
                    v["http_method"],
                    v["url"],
                    v["parameter"],
                    v["filename"],
                    v["line_number"],
                    v["description"],
                    v["code_location"],
                    v["poc"],
                    v["remediation"],
                    user["sub"],
                    v["impact_weight"],
                    v["difficulty_tier"],
                    v["weight_verified"],
                ),
            )
            vuln_id_map[v["id"]] = cursor.lastrowid

        cursor = await db.execute(
            "SELECT * FROM chains WHERE app_id = ? AND invalidated_at_revision IS NULL",
            (clone_from,),
        )
        source_chains = await cursor.fetchall()
        for c in source_chains:
            cursor = await db.execute(
                """INSERT INTO chains (app_id, chain_id, title, severity, impact_weight,
                   description, existed_since_revision)
                   VALUES (?, ?, ?, ?, ?, ?, 1)""",
                (app_id, c["chain_id"], c["title"], c["severity"], c["impact_weight"], c["description"]),
            )
            new_chain_pk = cursor.lastrowid
            cursor = await db.execute(
                "SELECT vuln_id, step_order FROM chain_members WHERE chain_pk = ? ORDER BY step_order",
                (c["id"],),
            )
            for m in await cursor.fetchall():
                new_vuln_id = vuln_id_map.get(m["vuln_id"])
                if new_vuln_id is not None:
                    await db.execute(
                        "INSERT INTO chain_members (chain_pk, vuln_id, step_order) VALUES (?, ?, ?)",
                        (new_chain_pk, new_vuln_id, m["step_order"]),
                    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    result = dict(app)
    result["tech_stack"] = await _get_tech_stack(db, app_id)
    return result


async def update_app(
    db,
    user,
    app_id: int,
    name: str,
    version: str,
    description: str | None,
    url: str | None,
    visibility: str,
    team_id: int | None,
    tech_stack: str,
    benchmark_verified=None,
    source_repository=SOURCE_UNSET,
    source_commit=SOURCE_UNSET,
    source_directory=SOURCE_UNSET,
) -> dict:
    """Update an existing app. Returns the updated row as a dict.

    *benchmark_verified* is tri-state: ``None`` leaves the flag alone. It marks
    an app whose vulns have actually been hand-reviewed (weights/tiers set, not
    just backfilled), so it is a deliberate setting rather than something a
    routine app edit toggles by omission.
    Omitted source fields are preserved; explicit ``None`` clears them.

    Raises ``ValueError`` if app not found.
    Raises ``PermissionError`` if access denied or visibility invalid.
    """
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _require_app_write(db, user, app)

    url = _validate_url(url)
    visibility = _validate_visibility(user, visibility, team_id)
    if visibility == "team":
        await _validate_team_access(db, user, team_id)

    if source_repository is SOURCE_UNSET:
        source_repository = app["source_repository"]
    if source_commit is SOURCE_UNSET:
        source_commit = app["source_commit"]
    if source_directory is SOURCE_UNSET:
        source_directory = app["source_directory"]
    source_repository = _validate_source_repository(source_repository)
    source_commit = _validate_source_commit(source_commit)
    source_directory = _validate_source_directory(source_directory)

    await db.execute(
        """UPDATE apps SET name=?, version=?, description=?, url=?,
           visibility=?, team_id=?, source_repository=?, source_commit=?, source_directory=?,
           updated_at=datetime('now') WHERE id=?""",
        (name, version, description, url, visibility, team_id,
         source_repository, source_commit, source_directory, app_id),
    )
    if benchmark_verified is not None:
        await db.execute(
            "UPDATE apps SET benchmark_verified=? WHERE id=?",
            (1 if benchmark_verified in (True, 1, "1", "true", "yes") else 0, app_id),
        )
    await _save_tech_stack(db, app_id, tech_stack)
    await db.commit()

    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    result = dict(app)
    result["tech_stack"] = await _get_tech_stack(db, app_id)
    return result


async def delete_app(db, user, app_id: int) -> None:
    """Delete an app. Cascade handles vulns/scans.

    Raises ``ValueError`` if not found, ``PermissionError`` if access denied.
    """
    cursor = await db.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
    app = await cursor.fetchone()
    if not app:
        raise ValueError("App not found")

    await _require_app_write(db, user, app)

    await db.execute("DELETE FROM apps WHERE id = ?", (app_id,))
    await db.commit()


async def get_user_teams(db, user_id) -> list:
    """Return teams the user belongs to (for form dropdowns)."""
    cursor = await db.execute(
        """SELECT teams.id, teams.name FROM teams
           JOIN team_members ON team_members.team_id = teams.id
           WHERE team_members.user_id = ?
           ORDER BY teams.name""",
        (user_id,),
    )
    return await cursor.fetchall()

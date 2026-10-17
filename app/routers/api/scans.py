from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import FileResponse
from app.database import get_connection
from app.services import scans as scans_service
from app.services import labels as labels_service
from app.services import scoring as scoring_service
from app.services import audit as audit_service
from app.dependencies import require_user, require_scope, get_current_user

router = APIRouter()
submit_router = APIRouter()
labels_router = APIRouter()


# ---------------------------------------------------------------------------
# Scan CRUD (mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.get("")
async def list_scans(
    request: Request,
    app_id: str = "",
    scanner: str = "",
    latest: str = "",
    q: str = "",
    label: list[str] = Query(default=[]),
    label_match: Literal["all", "any"] = "all",
    filter: str = "",
    include_metrics: bool = False,
):
    user = request.state.user
    db = await get_connection()
    try:
        parsed_app_id = None
        if app_id:
            try:
                parsed_app_id = int(app_id)
            except ValueError:
                raise HTTPException(status_code=404, detail="Invalid app_id")

        result = await scans_service.list_scans(
            db, user,
            app_id=parsed_app_id,
            scanner=scanner,
            latest=latest,
            q=q,
            label=label,
            label_match=label_match,
            filter=filter,
            include_metrics=include_metrics,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {
        "scans": [dict(s) for s in result["scans"]],
        "coverage": result.get("coverage"),
        "scan_labels_map": result["scan_labels_map"],
        "scanners": result["scanners"],
        "apps_list": [dict(a) for a in result["apps_list"]],
        "all_labels": result["all_labels"],
        "user_teams": [dict(t) for t in result["user_teams"]],
    }


@router.get("/{scan_id}")
async def get_scan(request: Request, scan_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await scans_service.get_scan(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.put("/{scan_id}")
async def update_scan(request: Request, scan_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()
    db = await get_connection()
    try:
        scan = await scans_service.update_scan(db, user, scan_id, body)
    except ValueError as e:
        msg = str(e)
        # Validation errors (e.g. trying to publish a scan on a private app)
        # are 400, not 404.
        if msg.startswith("Cannot publish") or "must" in msg:
            raise HTTPException(status_code=400, detail=msg)
        raise HTTPException(status_code=404, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True, "scan": scan}


@router.delete("/{scan_id}")
async def delete_scan(request: Request, scan_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    db = await get_connection()
    try:
        await scans_service.delete_scan(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True}


# ---------------------------------------------------------------------------
# Finding operations (mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/findings/{finding_id}/match")
async def match_finding(request: Request, scan_id: int, finding_id: int):
    """Set a finding's matches: ``{vuln_ids: [], chain_ids: []}``.

    Full replacement, so sending both empty clears the finding back to
    pending. A finding can match several vulns and/or chains at once — see
    app/services/scans.py::match_finding.

    The legacy single-value bodies (``{vuln_id: N}`` / ``{chain_id: N}``, with
    ``null`` to clear) are still accepted: a stale copy of the importer lives
    outside this repo and still sends them.
    """
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()
    if "vuln_ids" in body or "chain_ids" in body:
        vuln_ids = body.get("vuln_ids") or []
        chain_ids = body.get("chain_ids") or []
    else:
        vuln_id = body.get("vuln_id")
        chain_id = body.get("chain_id")
        if vuln_id is not None and chain_id is not None:
            raise HTTPException(
                status_code=400,
                detail="A finding can match a vuln or a chain, not both",
            )
        vuln_ids = [vuln_id] if vuln_id is not None else []
        chain_ids = [chain_id] if chain_id is not None else []
    if not isinstance(vuln_ids, list) or not isinstance(chain_ids, list):
        raise HTTPException(status_code=400, detail="vuln_ids/chain_ids must be lists")

    db = await get_connection()
    try:
        result = await scans_service.match_finding(
            db, user, scan_id, finding_id, vuln_ids, chain_ids
        )
    except ValueError as e:
        msg = str(e)
        status = 400 if "must be integers" in msg else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.post("/{scan_id}/findings/{finding_id}/mark-fp")
async def mark_finding_fp(request: Request, scan_id: int, finding_id: int):
    """Mark a finding as a false positive.

    Optional body ``{"fp_group": "..."}`` clusters findings describing the same
    non-issue so precision counts one FP instead of three — the FP-side
    equivalent of matching several findings to one vuln.
    """
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    raw = await request.body()
    fp_group = None
    penalty_kwargs = {}
    if raw:
        import json
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise HTTPException(status_code=400, detail="Expected a JSON object")
            fp_group = body.get("fp_group")
            if fp_group is not None and not isinstance(fp_group, str):
                raise HTTPException(status_code=400, detail="fp_group must be a string or null")
            if "fp_impact_weight" in body:
                penalty = body["fp_impact_weight"]
                if penalty is not None and (type(penalty) is not int or penalty not in (1, 3, 9, 27)):
                    raise HTTPException(status_code=400, detail="fp_impact_weight must be null or one of 1, 3, 9, 27")
                penalty_kwargs["fp_impact_weight"] = penalty
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

    db = await get_connection()
    try:
        await scans_service.mark_finding_fp(db, user, scan_id, finding_id, fp_group, **penalty_kwargs)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True, "fp_group": fp_group}


@router.post("/{scan_id}/chains/{chain_pk}/confirm")
async def confirm_chain_credit(request: Request, scan_id: int, chain_pk: int):
    """Explicitly confirm this scan demonstrates *chain_pk* end to end.

    Matching every member is necessary but not sufficient for chain credit —
    see app/services/scans.py::confirm_chain_credit. Optional body
    ``{"notes": "..."}`` records why the reviewer is confident.
    """
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    raw = await request.body()
    notes = None
    if raw:
        import json
        try:
            notes = (json.loads(raw) or {}).get("notes")
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

    db = await get_connection()
    try:
        result = await scans_service.confirm_chain_credit(db, user, scan_id, chain_pk, notes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return result


@router.delete("/{scan_id}/chains/{chain_pk}/confirm")
async def revoke_chain_credit(request: Request, scan_id: int, chain_pk: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")

    db = await get_connection()
    try:
        result = await scans_service.revoke_chain_credit(db, user, scan_id, chain_pk)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("/{scan_id}/findings/{finding_id}/ignore")
async def set_finding_ignored(request: Request, scan_id: int, finding_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()
    ignored = bool(body.get("ignored", True))

    db = await get_connection()
    try:
        await scans_service.set_finding_ignored(db, user, scan_id, finding_id, ignored)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True, "is_ignored": ignored}


@router.post("/{scan_id}/findings/{finding_id}/promote")
async def promote_finding(request: Request, scan_id: int, finding_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    raw = await request.body()
    overrides = {}
    if raw:
        import json
        try:
            overrides = json.loads(raw) or {}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

    db = await get_connection()
    try:
        result = await scans_service.promote_finding(
            db, user, scan_id, finding_id, overrides=overrides,
        )
    except ValueError as e:
        msg = str(e)
        # Missing/invalid existed_since, weight or tier is a bad request; a
        # missing scan or finding is a 404.
        status = 400 if ("must be" in msg or "existed_since" in msg) else 404
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.post("/{scan_id}/findings/{finding_id}/promote-chain")
async def promote_finding_to_chain(request: Request, scan_id: int, finding_id: int):
    """Register a missing chain from a finding that reports it, and map the
    finding to it. Body: {title?, severity, member_vuln_ids, description?}."""
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()

    db = await get_connection()
    try:
        result = await scans_service.promote_finding_to_chain(
            db, user, scan_id, finding_id, body or {},
        )
    except ValueError as e:
        msg = str(e)
        status = 404 if msg in ("Finding not found", "Scan not found") else 400
        raise HTTPException(status_code=status, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("/{scan_id}/rematch")
async def rematch_scan(request: Request, scan_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")

    db = await get_connection()
    try:
        result = await scans_service.rematch_scan(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.get("/{scan_id}/history")
async def get_scan_history(request: Request, scan_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        entries = await scans_service.list_scan_history(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"entries": entries}


# ---------------------------------------------------------------------------
# Scan state (zip blob of source directory; mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/state")
async def upload_scan_state(request: Request, scan_id: int):
    """Upload a zip as the scan's source-of-truth state. Send as
    application/zip body; filename in X-Filename header (optional)."""
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    content = await request.body()
    filename = request.headers.get("x-filename") or f"scan-{scan_id}.zip"
    db = await get_connection()
    try:
        meta = await scans_service.set_scan_state(db, user, scan_id, content, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True, **meta}


@router.get("/{scan_id}/state")
async def download_scan_state(request: Request, scan_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        path, filename, size, sha = await scans_service.get_scan_state(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return FileResponse(
        path=str(path),
        filename=filename,
        media_type="application/zip",
        headers={"X-Scan-State-SHA256": sha or ""},
    )


@router.delete("/{scan_id}/state")
async def delete_scan_state_endpoint(request: Request, scan_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    db = await get_connection()
    try:
        await scans_service.delete_scan_state(db, user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Labels on scans (mounted at /api/scans)
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/labels")
async def add_label(request: Request, scan_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()
    name = body.get("name", "")
    color = body.get("color", "#f97316")

    db = await get_connection()
    try:
        result = await labels_service.add_label_to_scan(db, user, scan_id, name, color)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


@router.delete("/{scan_id}/labels/{label_id}")
async def remove_label(request: Request, scan_id: int, label_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")

    db = await get_connection()
    try:
        await labels_service.remove_label_from_scan(db, user, scan_id, label_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"ok": True}


# ---------------------------------------------------------------------------
# Scan submission (mounted at /api/apps)
# ---------------------------------------------------------------------------

@submit_router.post("/{app_id}/scans")
async def submit_scan(request: Request, app_id: int):
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()

    scanner_name = body.get("scanner_name", "")
    scanner_version = body.get("scanner_version") or None
    scan_date = body.get("scan_date", "")
    # Default scans to NOT public — making the parent-app visibility the
    # only thing the submitter actively opts into (vuln-0018). The service
    # also re-validates that is_public=1 requires a public parent app.
    is_public = 1 if body.get("is_public") is True else 0
    notes = body.get("notes")
    cost = body.get("cost")
    if cost is not None:
        try:
            cost = float(cost)
        except (TypeError, ValueError):
            cost = None
    tokens = body.get("tokens")
    if tokens is not None:
        try:
            tokens = int(tokens)
        except (TypeError, ValueError):
            tokens = None
    duration = body.get("duration")
    if duration is not None:
        try:
            duration = int(duration)
        except (TypeError, ValueError):
            duration = None
    findings_data = body.get("findings", [])
    scan_labels = body.get("labels")

    db = await get_connection()
    try:
        scan_id = await scans_service.submit_scan(
            db, user, app_id,
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            scan_date=scan_date,
            is_public=is_public,
            notes=notes,
            cost=cost,
            tokens=tokens,
            duration=duration,
            findings_data=findings_data,
            labels=scan_labels,
            run_details=body,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return {"scan_id": scan_id}


# ---------------------------------------------------------------------------
# Compare (mounted at /api/apps)
# ---------------------------------------------------------------------------

@submit_router.get("/{app_id}/compare")
async def compare_scans(request: Request, app_id: int, scans: str = ""):
    user = request.state.user

    db = await get_connection()
    try:
        if scans:
            scan_ids = [int(s) for s in scans.split(",") if s.strip().isdigit()]
            result = await scans_service.compare_scans(db, user, app_id, scan_ids)
        else:
            available = await scans_service.get_available_scans(db, user, app_id)
            result = {"available_scans": [dict(s) for s in available]}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()

    return result


# ---------------------------------------------------------------------------
# Ground-truth revisions, re-scoring and configuration reporting
# (mounted at /api/apps)
# ---------------------------------------------------------------------------

@submit_router.get("/{app_id}/revisions")
async def list_revisions(request: Request, app_id: int):
    """Ground-truth revision history for an app."""
    user = request.state.user
    db = await get_connection()
    try:
        from app.visibility import app_visibility_filter
        vis_clause, vis_params = app_visibility_filter(user)
        cursor = await db.execute(
            f"SELECT id FROM apps WHERE id = ? AND {vis_clause}", [app_id] + vis_params
        )
        if not await cursor.fetchone():
            raise HTTPException(status_code=404, detail="App not found")
        revisions = await scoring_service.list_revisions(db, app_id)
        latest = await scoring_service.latest_revision(db, app_id)
    finally:
        await db.close()
    return {"revisions": revisions, "latest_revision": latest}


@submit_router.post("/{app_id}/revisions")
async def create_revision(request: Request, app_id: int):
    """Open a new ground-truth revision.

    Body: ``{"reason": "weight_change" | "corpus_change" | "new_prior_vuln" |
    "vuln_invalidated", "notes": "..."}``. Weight changes require this: weights
    are immutable within a revision, so changing one without a new revision
    would make two numbers incomparable while looking identical.
    """
    user = await require_user(request)
    require_scope(user, "vuln-mapper")
    body = await request.json()

    db = await get_connection()
    try:
        from app.services import vulns as vulns_service
        app = await vulns_service._get_visible_app(db, user, app_id)
        await vulns_service._require_app_write(db, user, app)
        revision = await scoring_service.create_revision(
            db, app_id, body.get("reason", ""), body.get("notes"), user
        )
        message = f"{user['name']} opened ground-truth revision {revision}"
        if body.get("reason"):
            message += f" ({body['reason']})"
        await audit_service.record_audit_event(
            db, entity_type="vulnerability", action="revision_opened", actor=user,
            message=message, app_id=app_id,
            details={"revision": revision, "reason": body.get("reason"), "notes": body.get("notes")},
        )
        await db.commit()
    except ValueError as e:
        msg = str(e)
        raise HTTPException(status_code=400 if "must be one of" in msg else 404, detail=msg)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True, "revision": revision}


# ---------------------------------------------------------------------------
# Labels list (mounted at /api/labels)
# ---------------------------------------------------------------------------

@labels_router.get("")
async def list_labels():
    db = await get_connection()
    try:
        labels = await labels_service.list_labels(db)
    finally:
        await db.close()

    return {"labels": labels}

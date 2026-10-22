from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from app.database import get_connection
from app.dependencies import require_scope
from app.services import apps as apps_service

router = APIRouter()


def _optional_int(value, field: str) -> int | None:
    """Coerce a request-body field to an optional int without leaking the raw
    Python error message (vuln-0013)."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{field} must be an integer")


@router.get("")
async def list_apps(request: Request, q: str = "", filter: str = ""):
    user = request.state.user
    db = await get_connection()
    try:
        result = await apps_service.list_apps(db, user, q=q, filter=filter)
    finally:
        await db.close()
    return {"apps": result}


@router.get("/{app_id}")
async def get_app(request: Request, app_id: int):
    user = request.state.user
    db = await get_connection()
    try:
        result = await apps_service.get_app(db, user, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await db.close()
    return result


@router.post("")
async def create_app(request: Request):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    team_id = _optional_int(body.get("team_id"), "team_id")
    clone_from = _optional_int(body.get("clone_from"), "clone_from")
    db = await get_connection()
    try:
        app = await apps_service.create_app(
            db,
            user,
            name=body.get("name", ""),
            version=body.get("version", ""),
            description=body.get("description"),
            url=body.get("url"),
            visibility=body.get("visibility", "private"),
            team_id=team_id,
            tech_stack=body.get("tech_stack", ""),
            source_repository=body.get("source_repository", apps_service.SOURCE_UNSET),
            source_commit=body.get("source_commit", apps_service.SOURCE_UNSET),
            source_directory=body.get("source_directory", apps_service.SOURCE_UNSET),
            clone_from=clone_from,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"app": app}


@router.put("/{app_id}")
async def update_app(request: Request, app_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    body = await request.json()
    team_id = _optional_int(body.get("team_id"), "team_id")
    db = await get_connection()
    try:
        app = await apps_service.update_app(
            db,
            user,
            app_id,
            name=body.get("name", ""),
            version=body.get("version", ""),
            description=body.get("description"),
            url=body.get("url"),
            visibility=body.get("visibility", "private"),
            team_id=team_id,
            tech_stack=body.get("tech_stack", ""),
            source_repository=body.get("source_repository", apps_service.SOURCE_UNSET),
            source_commit=body.get("source_commit", apps_service.SOURCE_UNSET),
            source_directory=body.get("source_directory", apps_service.SOURCE_UNSET),
            # Absent means "leave alone" — see update_app.
            benchmark_verified=body.get("benchmark_verified"),
        )
    except ValueError as e:
        raise HTTPException(status_code=404 if str(e) == "App not found" else 400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"app": app}


@router.delete("/{app_id}")
async def delete_app(request: Request, app_id: int):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_scope(user, "full")

    db = await get_connection()
    try:
        await apps_service.delete_app(db, user, app_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    finally:
        await db.close()
    return {"ok": True}

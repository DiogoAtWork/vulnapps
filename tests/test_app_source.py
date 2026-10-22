"""Source provenance survives ordinary edits and cloning without leaking credentials."""

import aiosqlite
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.database import run_migrations
from app.routers.api import apps as apps_api


REPOSITORY = "https://github.com/example/target"
COMMIT = "a1" * 20
APP = {"name": "Target", "version": "1.2", "visibility": "private"}


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    async def connect():
        db = await aiosqlite.connect(tmp_path / "apps.db")
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys=ON")
        return db

    db = await connect()
    await run_migrations(db)
    await db.execute(
        "INSERT INTO users (id,name,email,password_hash,role) "
        "VALUES (1,'Reviewer','r@example.invalid','x','admin')"
    )
    await db.execute(
        "INSERT INTO users (id,name,email,password_hash,role) "
        "VALUES (2,'Other user','other@example.invalid','x','user')"
    )
    await db.commit()
    await db.close()
    app = FastAPI()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        other_user = request.headers.get("x-test-user") == "2"
        request.state.user = {
            "sub": 2 if other_user else 1, "name": "Other user" if other_user else "Reviewer",
            "role": "user" if other_user else "admin", "scope": "full",
        }
        return await call_next(request)

    app.include_router(apps_api.router, prefix="/api/apps")
    monkeypatch.setattr(apps_api, "get_connection", connect)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


async def test_source_fields_survive_edits_and_explicit_null_clears(client):
    response = await client.post("/api/apps", json={
        **APP, "source_repository": f" {REPOSITORY} ", "source_commit": COMMIT.upper(),
        "source_directory": " ./vibe-coding//target/ ",
    })
    assert response.status_code == 200, response.text
    created = response.json()["app"]
    assert created["version"] == "1.2"
    assert created["source_repository"] == REPOSITORY
    assert created["source_commit"] == COMMIT
    assert created["source_directory"] == "vibe-coding/target"
    app_url = f'/api/apps/{created["id"]}'
    response = await client.put(app_url, json={**APP, "description": "Readable summary"})
    assert response.status_code == 200, response.text
    updated = response.json()["app"]
    assert updated["source_repository"] == REPOSITORY
    assert updated["source_commit"] == COMMIT
    assert updated["source_directory"] == "vibe-coding/target"
    assert (await client.get(app_url)).json()["app"]["source_commit"] == COMMIT
    listed = (await client.get("/api/apps")).json()["apps"]
    assert listed[0]["app"]["source_repository"] == REPOSITORY
    response = await client.put(app_url, json={
        **APP, "source_repository": None, "source_commit": None, "source_directory": None,
    })
    assert response.status_code == 200, response.text
    assert response.json()["app"]["source_repository"] is None
    assert response.json()["app"]["source_commit"] is None
    assert response.json()["app"]["source_directory"] is None


async def test_clone_inherits_source_unless_each_field_is_overridden(client):
    response = await client.post("/api/apps", json={
        **APP, "source_repository": REPOSITORY, "source_commit": COMMIT,
        "source_directory": "vibe-coding/target",
    })
    source_id = response.json()["app"]["id"]
    response = await client.post("/api/apps", json={**APP, "clone_from": source_id})
    assert response.status_code == 200, response.text
    assert response.json()["app"]["source_repository"] == REPOSITORY
    assert response.json()["app"]["source_commit"] == COMMIT
    assert response.json()["app"]["source_directory"] == "vibe-coding/target"
    response = await client.post("/api/apps", json={
        **APP, "clone_from": source_id, "source_commit": None,
    })
    assert response.status_code == 200, response.text
    assert response.json()["app"]["source_repository"] == REPOSITORY
    assert response.json()["app"]["source_commit"] is None
    response = await client.post("/api/apps", json={
        **APP, "clone_from": source_id, "source_repository": "https://github.com/example/fork",
        "source_commit": "b" * 64, "source_directory": "other/target",
    })
    assert response.status_code == 200, response.text
    assert response.json()["app"]["source_repository"] == "https://github.com/example/fork"
    assert response.json()["app"]["source_commit"] == "b" * 64
    assert response.json()["app"]["source_directory"] == "other/target"


async def test_invalid_sources_rejected_before_create_or_update(client):
    response = await client.post("/api/apps", json={**APP, "source_repository": REPOSITORY})
    app_id = response.json()["app"]["id"]
    invalid_fields = [
        {"source_repository": value} for value in (
            "javascript:alert(1)", "https:///missing-host", "https://token@github.com/example/target",
            "https://user:secret@github.com/example/target", "https://github.com/has space", {},
        )
    ] + [{"source_commit": value} for value in ("main", "a" * 12, "z" * 40, 42)] + [
        {"source_directory": value} for value in (
            "/absolute", "../outside", "apps/../outside", "apps\\target", "apps/\x00target", {},
        )
    ]
    for fields in invalid_fields:
        for method, url in ((client.post, "/api/apps"), (client.put, f"/api/apps/{app_id}")):
            response = await method(url, json={**APP, **fields})
            assert response.status_code == 400, response.text
    apps = (await client.get("/api/apps")).json()["apps"]
    assert len(apps) == 1
    assert apps[0]["app"]["source_repository"] == REPOSITORY
    assert apps[0]["app"]["source_commit"] is None


async def test_cloning_inaccessible_private_app_does_not_copy_source_or_vulnerabilities(client, tmp_path):
    response = await client.post("/api/apps", json={
        **APP, "source_repository": REPOSITORY, "source_commit": COMMIT,
        "source_directory": "private/target",
    })
    source_id = response.json()["app"]["id"]
    async with aiosqlite.connect(tmp_path / "apps.db") as db:
        await db.execute(
            "INSERT INTO vulnerabilities (app_id,vuln_id,title,severity,created_by) "
            "VALUES (?,'PRIVATE-001','Private vulnerability','high',1)", (source_id,),
        )
        await db.commit()
    headers = {"x-test-user": "2"}
    assert (await client.get(f"/api/apps/{source_id}", headers=headers)).status_code == 404
    response = await client.post("/api/apps", json={**APP, "clone_from": source_id}, headers=headers)
    assert response.status_code == 200, response.text
    clone = response.json()["app"]
    assert clone["source_repository"] is None
    assert clone["source_commit"] is None
    assert clone["source_directory"] is None
    detail = (await client.get(f'/api/apps/{clone["id"]}', headers=headers)).json()
    assert detail["vulns"] == []

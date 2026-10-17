"""Reviewer penalties must survive API updates and reject malformed input."""

import json

import aiosqlite
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.database import run_migrations
from app.routers.api import scans as scans_api


async def test_fp_penalty_api_validates_persists_and_resets_review(tmp_path, monkeypatch):
    async def connect():
        db = await aiosqlite.connect(tmp_path / "review.db")
        db.row_factory = aiosqlite.Row
        return db

    db = await connect()
    await run_migrations(db)
    await db.execute("INSERT INTO users (id,name,email,password_hash,role) VALUES (1,'Reviewer','r@example.invalid','x','admin')")
    await db.execute("INSERT INTO apps (id,name,version,created_by,visibility) VALUES (1,'Demo','1',1,'private')")
    await db.execute("INSERT INTO scans (id,app_id,scanner_name,scan_date,submitted_by) VALUES (1,1,'Demo','2026-10-15',1)")
    await db.execute("INSERT INTO scan_findings (id,scan_id,title,vuln_type,url) VALUES (1,1,'Noise','Other','/noise')")
    await db.commit()
    await db.close()
    app = FastAPI()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        request.state.user = {"sub": 1, "name": "Reviewer", "role": "admin", "scope": "full"}
        return await call_next(request)

    async def authenticated_user(request):
        return request.state.user

    monkeypatch.setattr(scans_api, "require_user", authenticated_user)
    app.include_router(scans_api.router, prefix="/api/scans")
    monkeypatch.setattr(scans_api, "get_connection", connect)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        url = "/api/scans/1/findings/1/mark-fp"
        for value in (2, True, "9", 9.5, [], {}):
            response = await client.post(url, json={"fp_impact_weight": value})
            assert response.status_code == 400, response.text
        for payload in ([], None, {"fp_group": 9}):
            response = await client.post(url, content=json.dumps(payload))
            assert response.status_code == 400
        assert (await client.post(url, json={"fp_impact_weight": 9})).status_code == 200
        assert (await client.post(url, json={"fp_group": "duplicate"})).status_code == 200
        db = await connect()
        row = await (await db.execute("SELECT fp_impact_weight FROM scan_findings WHERE id=1")).fetchone()
        assert row["fp_impact_weight"] == 9
        await db.close()
        assert (await client.post(url, json={"fp_impact_weight": None})).status_code == 200
        db = await connect()
        row = await (await db.execute("SELECT fp_impact_weight FROM scan_findings WHERE id=1")).fetchone()
        assert row["fp_impact_weight"] is None
        await db.close()

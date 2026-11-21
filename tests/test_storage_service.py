import asyncio

import pytest

from backend.app import storage_service


def test_local_storage_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(storage_service, "STORAGE_BACKEND", "local")
    monkeypatch.setattr(storage_service, "DOCUMENT_STORAGE_DIR", tmp_path / "documents")
    reference = asyncio.run(storage_service.save_file("documents/user-a/doc.pdf", b"%PDF-test", "application/pdf"))
    assert (tmp_path / "documents/user-a/doc.pdf").read_bytes() == b"%PDF-test"
    assert asyncio.run(storage_service.read_file(reference)) == b"%PDF-test"
    asyncio.run(storage_service.delete_file(reference))
    assert not (tmp_path / "documents/user-a/doc.pdf").exists()


def test_local_storage_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(storage_service, "DOCUMENT_STORAGE_DIR", tmp_path / "documents")
    with pytest.raises(ValueError):
        storage_service._local_path("../outside.pdf")


def test_frontend_and_health_routes_are_available():
    from fastapi.testclient import TestClient
    from backend.app.main import app

    with TestClient(app) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "SecureSign Cloud" in home.text
        asset = client.get("/static/app.js")
        assert asset.status_code == 200
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

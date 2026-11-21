"""Storage adapter for local development and private Vercel Blob storage.

Database records store opaque storage references. In Vercel mode these are
private Blob pathnames; in local mode they are absolute paths under storage/.
"""
from pathlib import Path, PurePosixPath

from .config import DOCUMENT_STORAGE_DIR, STORAGE_BACKEND


def _local_path(reference: str) -> Path:
    root = DOCUMENT_STORAGE_DIR.resolve()
    candidate = Path(reference)
    if not candidate.is_absolute():
        posix = PurePosixPath(reference)
        if posix.is_absolute() or not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
            raise ValueError("Storage reference không hợp lệ.")
        parts = posix.parts[1:] if posix.parts[0] == "documents" else posix.parts
        if not parts:
            raise ValueError("Storage reference không hợp lệ.")
        candidate = root.joinpath(*parts)
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("Storage reference nằm ngoài vùng lưu trữ cho phép.")
    return resolved


def _blob_sdk():
    try:
        from vercel import blob
    except ImportError as exc:  # pragma: no cover - only relevant in Vercel mode
        raise RuntimeError("Thiếu package vercel-blob. Hãy cài requirements.txt.") from exc
    return blob


async def save_file(reference: str, content: bytes, content_type: str) -> str:
    if STORAGE_BACKEND == "vercel_blob":
        blob = _blob_sdk()
        await blob.put_blob(
            reference,
            content,
            access="private",
            content_type=content_type,
        )
        return reference

    if STORAGE_BACKEND != "local":
        raise RuntimeError(f"STORAGE_BACKEND không được hỗ trợ: {STORAGE_BACKEND}")
    path = _local_path(reference)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return str(path)


async def read_file(reference: str) -> bytes:
    if STORAGE_BACKEND == "vercel_blob":
        blob = _blob_sdk()
        try:
            result = await blob.get_blob(reference, access="private")
        except blob.BlobNotFoundError as exc:
            raise FileNotFoundError(reference) from exc
        return result.body

    if STORAGE_BACKEND != "local":
        raise RuntimeError(f"STORAGE_BACKEND không được hỗ trợ: {STORAGE_BACKEND}")
    path = _local_path(reference)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise


async def delete_file(reference: str) -> None:
    if STORAGE_BACKEND == "vercel_blob":
        blob = _blob_sdk()
        await blob.delete_blob(reference)
        return

    if STORAGE_BACKEND != "local":
        raise RuntimeError(f"STORAGE_BACKEND không được hỗ trợ: {STORAGE_BACKEND}")
    _local_path(reference).unlink(missing_ok=True)


def storage_status() -> str:
    if STORAGE_BACKEND == "local":
        return "local"
    if STORAGE_BACKEND == "vercel_blob":
        return "vercel_blob"
    return "misconfigured"

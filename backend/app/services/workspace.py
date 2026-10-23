import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import UploadFile

from app.config import get_settings

ALLOWED_EXTENSIONS = {".py", ".zip"}
_CHUNK = 1024 * 1024


class UploadError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def create_workspace() -> Path:
    base = get_settings().workspace_dir or None
    if base:
        Path(base).mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="codesentinel-", dir=base))
    (root / "source").mkdir()
    return root


def cleanup_workspace(root: Path) -> None:
    shutil.rmtree(root, ignore_errors=True)


def save_upload(upload: UploadFile, root: Path) -> Path:
    """Save the upload into root/source and return that directory."""
    settings = get_settings()
    name = (upload.filename or "").replace("\\", "/").split("/")[-1]
    ext = Path(name).suffix.lower()
    if not name or ext not in ALLOWED_EXTENSIONS:
        raise UploadError(400, "Only a .py file or a .zip archive is supported.")

    source = root / "source"
    dest = source / name if ext == ".py" else root / "upload.zip"
    limit = settings.max_upload_mb * _CHUNK
    written = 0
    with open(dest, "wb") as out:
        while chunk := upload.file.read(_CHUNK):
            written += len(chunk)
            if written > limit:
                raise UploadError(413, f"File is larger than {settings.max_upload_mb} MB.")
            out.write(chunk)
    if written == 0:
        raise UploadError(400, "Uploaded file is empty.")

    if ext == ".zip":
        _safe_extract(dest, source)
        dest.unlink()
    return source


def _safe_extract(zip_path: Path, target: Path) -> None:
    settings = get_settings()
    limit = settings.max_unzipped_mb * _CHUNK
    root = target.resolve()
    total = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > settings.max_zip_files:
                raise UploadError(400, f"Archive has more than {settings.max_zip_files} files.")
            for info in infos:
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue  # skip symlinks
                dest = (target / info.filename).resolve()
                if dest != root and root not in dest.parents:
                    raise UploadError(400, "Archive contains unsafe file paths.")
                if info.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as out:
                    while chunk := src.read(_CHUNK):
                        total += len(chunk)
                        if total > limit:
                            raise UploadError(400, f"Archive is larger than {settings.max_unzipped_mb} MB when extracted.")
                        out.write(chunk)
    except (zipfile.BadZipFile, RuntimeError):
        raise UploadError(400, "Could not read the zip file (corrupt or password-protected).")

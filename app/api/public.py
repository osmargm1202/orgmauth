from pathlib import Path, PurePosixPath

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth.jwt import get_jwks
from app.database import get_db
from app.models import Application, User, UserDeniedApp
from app.schemas import (
    ApplicationResponse,
    UserResponse,
    AllowedAppsResponse,
    DocumentationEntry,
    DocumentationIndexResponse,
    JWKSResponse,
)
from app.config import settings

router = APIRouter(tags=["public"])
DOCS_ROOT = Path(__file__).resolve().parents[2] / "docs"


def _available_docs() -> dict[str, Path]:
    return {
        path.relative_to(DOCS_ROOT).as_posix(): path
        for path in sorted(DOCS_ROOT.rglob("*.md"))
    }


def _resolve_doc_path(doc_path: str) -> Path:
    normalized = PurePosixPath(doc_path)
    safe_path = normalized.as_posix()

    if (
        not doc_path
        or normalized.is_absolute()
        or safe_path in {"", "."}
        or any(part == ".." for part in normalized.parts)
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documentation not found",
        )

    resolved = _available_docs().get(safe_path)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documentation not found",
        )

    return resolved


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
def get_jwks_document(response: Response):
    response.headers["Cache-Control"] = settings.JWKS_CACHE_CONTROL
    return get_jwks()


@router.get("/developer/docs", response_model=DocumentationIndexResponse)
def list_documentation(request: Request):
    docs = [
        DocumentationEntry(
            path=doc_path,
            url=str(request.url_for("get_documentation_doc", doc_path=doc_path)),
        )
        for doc_path in _available_docs()
    ]
    return DocumentationIndexResponse(docs=docs)


@router.get(
    "/developer/docs/{doc_path:path}",
    response_class=PlainTextResponse,
    name="get_documentation_doc",
)
def get_documentation_doc(doc_path: str):
    document = _resolve_doc_path(doc_path)
    return PlainTextResponse(
        document.read_text(encoding="utf-8"), media_type="text/markdown"
    )


@router.get("/apps", response_model=list[ApplicationResponse])
def list_applications(db: Session = Depends(get_db)):
    apps = db.query(Application).order_by(Application.name).all()
    return apps


@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return users


@router.get("/users/{email}/allowed-apps", response_model=AllowedAppsResponse)
def get_user_allowed_apps(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    all_apps = db.query(Application.name).order_by(Application.name).all()
    all_app_names = [app.name for app in all_apps]

    denied = (
        db.query(UserDeniedApp.app_name).filter(UserDeniedApp.user_id == user.id).all()
    )
    denied_app_names = [d.app_name for d in denied]

    allowed_app_names = [app for app in all_app_names if app not in denied_app_names]

    return AllowedAppsResponse(
        email=email,
        denied_apps=denied_app_names,
        allowed_apps=allowed_app_names,
    )

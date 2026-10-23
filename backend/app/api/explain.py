from fastapi import APIRouter, HTTPException

from app import db
from app.ai import service
from app.models.schemas import AIAnalysis, Finding

router = APIRouter(tags=["ai"])


@router.post("/findings/{finding_id}/explain", response_model=AIAnalysis)
def explain_finding(finding_id: str, refresh: bool = False) -> AIAnalysis:
    """Explain one finding. The result is saved; pass refresh=true to generate it again."""
    data = db.get_finding(finding_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding = Finding(**{k: data[k] for k in Finding.model_fields})
    return service.explain_finding(finding, refresh)


@router.get("/findings/{finding_id}/explanation", response_model=AIAnalysis)
def get_explanation(finding_id: str) -> AIAnalysis:
    """The saved explanation, if one exists."""
    analysis = db.get_analysis(finding_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="No explanation yet.")
    return analysis

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import blockchain
import chain
import report as report_lib
import service

app = FastAPI(title="ChainShield API", version="0.2.0",
              description="Explainable wallet risk analysis with tamper-evident reports.")


class AnalyzeRequest(BaseModel):
    address: str
    chain_id: int = 1
    use_cache: bool = True


class AnchorRequest(BaseModel):
    report: dict


class VerifyRequest(BaseModel):
    report: dict
    expected_hash: Optional[str] = None
    check_onchain: bool = False


def _analyze(req: AnalyzeRequest) -> dict:
    if not blockchain.is_valid_address(req.address):
        raise HTTPException(status_code=422,
                            detail="Invalid address. Use 0x followed by 40 hexadecimal characters.")
    try:
        return service.analyze_address(req.address, req.chain_id, req.use_cache)
    except blockchain.BlockchainError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/chain/status")
def chain_status():
    return chain.status()


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Full risk analysis: score, rating, findings with evidence, graph, transactions."""
    return _analyze(req)


@app.post("/report")
def make_report(req: AnalyzeRequest):
    """Analyze, then return the report and its SHA-256 hash."""
    result = _analyze(req)
    rep = report_lib.build_report(result)
    return {"report": rep, "report_hash": report_lib.hash_report(rep)}


@app.post("/anchor")
def anchor(req: AnchorRequest):
    """Hash the given report and store the hash on the test network. The report itself is never sent."""
    report_hash = report_lib.hash_report(req.report)
    try:
        return {"report_hash": report_hash, **chain.anchor_hash(report_hash)}
    except chain.ChainError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/verify")
def verify(req: VerifyRequest):
    """Re-hash a report. Optionally compare with an expected hash and look it up on-chain."""
    out = {"computed_hash": report_lib.hash_report(req.report)}
    if req.expected_hash:
        out.update(report_lib.verify_report(req.report, req.expected_hash))
    if req.check_onchain:
        try:
            record = chain.get_anchor(out["computed_hash"])
            out["onchain"] = {"checked": True, "anchored": record is not None, **(record or {})}
        except chain.ChainError as e:
            out["onchain"] = {"checked": False, "error": str(e)}
    return out
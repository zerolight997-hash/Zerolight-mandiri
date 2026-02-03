import os
from datetime import date
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from supabase import create_client, Client


# ----- Config & Supabase client -----

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set in environment")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Simple global threshold for example; you can move this to `policies` table later.
ANOMALY_THRESHOLD = 10

app = FastAPI(
    title="Zerolight Portal Gateway API",
    description="Zero-Trust gateway for domains and bots (Record → Analyze → Validate → Document → Report).",
    version="0.1.0",
)


# ----- Pydantic models for responses -----

class AllowedDomain(BaseModel):
    domain_name: str
    role: str


class StatusResponse(BaseModel):
    status: str
    reason: str | None = None


# ----- Health / info -----

@app.get("/", response_model=Dict[str, Any])
def root():
    return {
        "service": "zerolight-portal-gateway",
        "status": "ok",
        "message": "Zero-Trust Digital Infrastructure Compliance Gateway",
    }


# ----- Core gateway: /go/{domain} -----

@app.get("/go/{domain}", responses={302: {"description": "Redirect to domain"}})
def go(domain: str):
    """
    Zero-trust gate for outgoing access to protected domains.
    1) Record request
    2) Analyze anomalies
    3) Validate status
    4) Decide publish/unpublish
    5) Redirect or return compliance hold
    """
    # 1) Look up domain
    result = (
        supabase.table("domains")
        .select("id, domain_name, status")
        .eq("domain_name", domain)
        .single()
        .execute()
    )

    if not result.data:
        raise HTTPException(status_code=404, detail="Domain not found")

    domain_row = result.data

    # 2) Analyze anomalies (today)
    metrics = (
        supabase.table("metrics_daily")
        .select("anomalies")
        .eq("domain_id", domain_row["id"])
        .eq("metric_date", date.today().isoformat())
        .maybe_single()
        .execute()
    )

    anomalies = 0
    if metrics.data:
        # metrics.data may be dict or None
        anomalies = metrics.data.get("anomalies", 0)

    # 3) Validate policy: simple threshold
    if domain_row["status"] != "online" or anomalies >= ANOMALY_THRESHOLD:
        # Document decision as event (optional; you can also use decisions table separately)
        supabase.table("events").insert(
            {
                "domain_id": domain_row["id"],
                "event_type": "access_blocked",
                "actor": "portal-gateway",
                "metadata": {
                    "reason": "Domain offline or anomalies above threshold",
                    "status": domain_row["status"],
                    "anomalies_today": anomalies,
                    "threshold": ANOMALY_THRESHOLD,
                },
            }
        ).execute()

        return JSONResponse(
            status_code=423,
            content={
                "status": "offline",
                "reason": "Temporarily unpublished or under compliance hold",
            },
        )

    # 4) Document allowed access
    supabase.table("events").insert(
        {
            "domain_id": domain_row["id"],
            "event_type": "access_allowed",
            "actor": "portal-gateway",
            "metadata": {
                "anomalies_today": anomalies,
                "threshold": ANOMALY_THRESHOLD,
            },
        }
    ).execute()

    # 5) Redirect to target domain
    return RedirectResponse(url=f"https://{domain}", status_code=302)


# ----- Admin: recalc decisions -----

@app.post("/admin/recalc", response_model=StatusResponse)
def recalc():
    """
    Simple policy evaluation:
    - If anomalies_today < threshold → publish (online)
    - Else → unpublish (offline)
    Writes to `decisions` table and updates `domains.status`.
    """
    domains_resp = supabase.table("domains").select("id, domain_name").execute()
    domains = domains_resp.data or []

    for domain in domains:
        metrics = (
            supabase.table("metrics_daily")
            .select("anomalies")
            .eq("domain_id", domain["id"])
            .eq("metric_date", date.today().isoformat())
            .maybe_single()
            .execute()
        )
        anomalies = 0
        if metrics.data:
            anomalies = metrics.data.get("anomalies", 0)

        decision = "publish" if anomalies < ANOMALY_THRESHOLD else "unpublish"
        reason = (
            "Anomalies within threshold"
            if decision == "publish"
            else "Anomaly threshold exceeded"
        )

        # Log decision
        supabase.table("decisions").insert(
            {
                "domain_id": domain["id"],
                "decision": decision,
                "reason": reason,
                "evidence": {
                    "anomalies_today": anomalies,
                    "threshold": ANOMALY_THRESHOLD,
                },
            }
        ).execute()

        # Update domain status
        supabase.table("domains").update(
            {
                "status": "online" if decision == "publish" else "offline",
                "last_unpublish_reason": None
                if decision == "publish"
                else "Anomaly threshold exceeded",
            }
        ).eq("id", domain["id"]).execute()

    return StatusResponse(status="ok", reason="Recalculated for all domains")


# ----- For bots: list allowed domains -----

@app.get("/allowed", response_model=List[AllowedDomain])
def allowed_domains():
    """
    Endpoint for bots/clients to ask:
    - Which domains are currently online and allowed?
    """
    resp = (
        supabase.table("domains")
        .select("domain_name, role, status")
        .eq("status", "online")
        .execute()
    )
    data = resp.data or []
    return [
        AllowedDomain(domain_name=row["domain_name"], role=row["role"])
        for row in data
    ]

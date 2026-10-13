import os, logging, threading, time
import requests
from fastapi import FastAPI, HTTPException
from . import graph, queries

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("graph-service")

SOC_URL = os.getenv("SOC_URL", "http://soc-event-service:8084")
SYNC_SECONDS = int(os.getenv("SYNC_SECONDS", "20"))
app = FastAPI(title="ITRI623 Graph Service")
state = {"lastSync": None, "alerts": 0, "error": None}


def sync_once():
    alerts = requests.get(f"{SOC_URL}/api/alerts", timeout=10).json()
    events = requests.get(f"{SOC_URL}/api/events", timeout=10).json()
    by_id = {e["eventId"]: e for e in events}
    for a in alerts:
        graph.upsert_alert(a, by_id)
    state.update(lastSync=time.strftime("%Y-%m-%d %H:%M:%S"), alerts=len(alerts), error=None)
    return len(alerts)


def loop():
    while True:
        try:
            sync_once()
        except Exception as e:  # keep the loop alive if SOC service or Neo4j is briefly down
            state["error"] = str(e)
            log.warning("sync failed: %s", e)
        time.sleep(SYNC_SECONDS)


@app.on_event("startup")
def startup():
    for attempt in range(30):          # Neo4j takes a while to accept connections
        try:
            graph.seed()
            break
        except Exception as e:
            log.warning("waiting for Neo4j (%s)", e)
            time.sleep(5)
    threading.Thread(target=loop, daemon=True).start()


@app.get("/health")
def health():
    return {"status": "UP", **state}


@app.post("/sync")
def sync():
    return {"alertsSynced": sync_once()}


@app.get("/graph/alerts")
def q1(service: str):
    return queries.alerts_for_service(service)


@app.get("/graph/high-severity-users")
def q2():
    return queries.users_high_severity()


@app.get("/graph/threats")
def q3(service: str):
    return queries.threats_for_service(service)


@app.get("/graph/controls")
def q4(alertId: str):
    return queries.controls_for_alert(alertId)


@app.get("/graph/dependency-impact")
def q5(service: str):
    return queries.dependency_impact(service)


@app.get("/graph/evidence/{alert_id}")
def evidence(alert_id: str):
    r = queries.alert_evidence(alert_id)
    if not r or r[0]["alertId"] is None:
        raise HTTPException(404, "alert not in graph")
    return r[0]

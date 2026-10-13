import os, re, logging
from neo4j import GraphDatabase

log = logging.getLogger("graph")
URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
USER = os.getenv("NEO4J_USER", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD", "itri623pass")

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))

# rule name -> threat the alert is *consistent with* (never "confirms")
RULE_TO_THREAT = {
    "Multiple Failed Logins": "T-01",
    "Unauthorised Endpoint Access": "T-02",
    "Abnormal Request Rate": "T-03",
    "Service Failure": "T-03",
}


def run(query, **params):
    with driver.session() as s:
        return [r.data() for r in s.run(query, **params)]


def seed():
    path = os.path.join(os.path.dirname(__file__), "seed.cypher")
    text = open(path, encoding="utf-8").read()
    lines = [l for l in text.splitlines() if not l.strip().startswith("//")]
    statements = [s.strip() for s in "\n".join(lines).split(";") if s.strip()]
    with driver.session() as s:
        for st in statements:
            s.run(st).consume()
    log.info("Seeded %d statements", len(statements))


def normalise_endpoint(path):
    return re.sub(r"/\d+(?=/|$)", "/{id}", path) if path else None


def upsert_event(ev):
    run("""
        MERGE (e:Event {id:$id})
        SET e.timestamp=$timestamp, e.eventType=$eventType, e.severity=$severity,
            e.httpMethod=$httpMethod, e.statusCode=$statusCode, e.message=$message,
            e.sourceIp=$sourceIp, e.correlationId=$correlationId
        """, id=ev["eventId"], timestamp=ev.get("timestamp"), eventType=ev.get("eventType"),
        severity=ev.get("severity"), httpMethod=ev.get("httpMethod"), statusCode=ev.get("statusCode"),
        message=ev.get("message"), sourceIp=ev.get("sourceIp"), correlationId=ev.get("correlationId"))
    if ev.get("serviceName"):
        run("MATCH (e:Event {id:$id}) MERGE (s:Service {name:$n}) MERGE (e)-[:GENERATED_BY]->(s)",
            id=ev["eventId"], n=ev["serviceName"])
    if ev.get("userId"):
        run("MATCH (e:Event {id:$id}) MERGE (u:User {id:$u}) MERGE (u)-[:TRIGGERED]->(e)",
            id=ev["eventId"], u=ev["userId"])
    ep = normalise_endpoint(ev.get("endpoint"))
    if ep:
        run("MATCH (e:Event {id:$id}) MERGE (p:Endpoint {path:$p}) MERGE (e)-[:TARGETED]->(p)",
            id=ev["eventId"], p=ep)


def upsert_alert(alert, events_by_id):
    aid = alert["alertId"]
    run("""
        MERGE (a:Alert {id:$id})
        SET a.ruleName=$rule, a.severity=$sev, a.status=$status, a.description=$desc,
            a.timestamp=$ts, a.recommendedAction=$action
        """, id=aid, rule=alert.get("ruleName"), sev=alert.get("severity"), status=alert.get("status"),
        desc=alert.get("description"), ts=alert.get("timestamp"), action=alert.get("recommendedAction"))
    for eid in alert.get("relatedEvents") or []:
        ev = events_by_id.get(eid)
        if not ev:
            continue
        upsert_event(ev)
        run("MATCH (e:Event {id:$e}),(a:Alert {id:$a}) MERGE (e)-[:CREATED_ALERT]->(a)", e=eid, a=aid)
    if alert.get("affectedService"):
        run("MATCH (a:Alert {id:$a}) MERGE (s:Service {name:$s}) MERGE (a)-[:AFFECTS]->(s)",
            a=aid, s=alert["affectedService"])
    tid = RULE_TO_THREAT.get(alert.get("ruleName"))
    if tid:
        run("MATCH (a:Alert {id:$a}),(t:Threat {id:$t}) MERGE (a)-[:INDICATES]->(t)", a=aid, t=tid)

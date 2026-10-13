"""GraphRAG: Route A (exact Cypher by alert id) and Route B (vector + graph expansion).
Answers are built from a fixed Observed / Interpretation / Response template, so every
statement traces back to retrieved graph evidence. No LLM is used."""
import re, logging
from .graph import run

log = logging.getLogger("rag")
MODEL = "BAAI/bge-small-en-v1.5"      # 384 dimensions, runs locally on CPU
_model = None


def _embedder():
    global _model
    if _model is None:
        from fastembed import TextEmbedding
        _model = TextEmbedding(MODEL)
    return _model


def embed(text):
    return [float(x) for x in next(iter(_embedder().embed([text])))]


def init():
    run("""CREATE VECTOR INDEX chunk_embeddings IF NOT EXISTS
           FOR (c:Chunk) ON (c.embedding)
           OPTIONS {indexConfig: {`vector.dimensions`: 384, `vector.similarity_function`: 'cosine'}}""")
    missing = run("MATCH (c:Chunk) WHERE c.embedding IS NULL RETURN c.id AS id, c.text AS text")
    for m in missing:
        run("MATCH (c:Chunk {id:$id}) SET c.embedding=$e", id=m["id"], e=embed(m["text"]))
    log.info("Embedded %d chunks", len(missing))


def _clean(rows, key):
    return [r for r in rows if r.get(key)]


def _join(items):
    items = [i for i in items if i]
    if not items:
        return "none"
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


# ---------------- Route A: exact Cypher ----------------
def route_a(alert_id):
    rows = run("""
        MATCH (a:Alert {id:$id})
        OPTIONAL MATCH (u:User)-[:TRIGGERED]->(e:Event)-[:CREATED_ALERT]->(a)
        OPTIONAL MATCH (e)-[:GENERATED_BY]->(s:Service)
        OPTIONAL MATCH (e)-[:TARGETED]->(ep:Endpoint)
        OPTIONAL MATCH (a)-[:INDICATES]->(t:Threat)
        OPTIONAL MATCH (t)-[:EXPLOITS]->(v:Vulnerability)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)
        OPTIONAL MATCH (d:Document)-[:SUPPORTS_RESPONSE_TO]->(t)
        OPTIONAL MATCH (i:Incident)-[:CONTAINS]->(a)
        RETURN a AS alert,
               collect(DISTINCT {user:u.id, event:e.id}) AS triggers,
               collect(DISTINCT {event:e.id, service:s.name}) AS generated,
               collect(DISTINCT ep.path) AS endpoints,
               t AS threat, collect(DISTINCT v) AS vulns, collect(DISTINCT c) AS controls,
               collect(DISTINCT d) AS docs, collect(DISTINCT i.id) AS incidents
        """, id=alert_id)
    if not rows or not rows[0]["alert"]:
        return None
    r = rows[0]
    a, t = r["alert"], r["threat"]
    events = sorted({x["event"] for x in r["triggers"] if x["event"]})
    users = sorted({x["user"] for x in r["triggers"] if x["user"]})
    services = sorted({x["service"] for x in r["generated"] if x["service"]})
    controls, docs, vulns = r["controls"], r["docs"], r["vulns"]

    observed = (f"Alert {alert_id} was raised by rule \"{a.get('ruleName')}\" with severity {a.get('severity')}. "
                f"{a.get('description')} It is based on {len(events)} event(s) ({_join(events)}) "
                f"triggered by user {_join(users)} on service {_join(services)}"
                + (f", targeting endpoint {_join(r['endpoints'])}." if r["endpoints"] else "."))
    if t:
        interpretation = (f"This pattern may indicate {t['name']} ({t.get('referenceId')}). The graph links the alert "
                          f"to this threat as consistent with it, not as confirmation. It may exploit "
                          f"{_join([v['id'] + ' ' + v['name'] for v in vulns])}. "
                          "Verify the account, source and timing before escalating.")
        response = (f"Follow procedure {_join([d['id'] + ': ' + d['title'] for d in docs])}. "
                    f"{_join([d.get('text') for d in docs])} "
                    f"Consider controls: {_join([c['name'] for c in controls])}. "
                    f"Recommended action from the rule: {a.get('recommendedAction')}")
    else:
        interpretation = "The graph holds no threat linked to this alert, so no interpretation can be given."
        response = f"Recommended action from the rule: {a.get('recommendedAction')}"

    rels = [f"{x['user']} TRIGGERED {x['event']}" for x in r["triggers"] if x["user"] and x["event"]]
    rels += [f"{e} CREATED_ALERT {alert_id}" for e in events]
    rels += [f"{x['event']} GENERATED_BY {x['service']}" for x in r["generated"] if x["service"] and x["event"]]
    rels += [f"{i} CONTAINS {alert_id}" for i in r["incidents"]]
    nodes = events + users + services + [alert_id] + r["incidents"]
    if t:
        rels.append(f"{alert_id} INDICATES {t['id']}")
        rels += [f"{t['id']} EXPLOITS {v['id']}" for v in vulns]
        rels += [f"{c['id']} MITIGATES {t['id']}" for c in controls]
        rels += [f"{d['id']} SUPPORTS_RESPONSE_TO {t['id']}" for d in docs]
        nodes += [t["id"]] + [v["id"] for v in vulns] + [c["id"] for c in controls] + [d["id"] for d in docs]
    return dict(observed=observed, interpretation=interpretation, response=response,
                evidence=dict(nodes=nodes, relationships=rels,
                              sources=[d["title"] for d in docs] + ([t["sourceUrl"]] if t and t.get("sourceUrl") else [])),
                retrievalMethod="cypher_exact", similarityScore=None)


# ---------------- Route B: vector + graph ----------------
def route_b(question, k=3):
    hits = run("""
        CALL db.index.vector.queryNodes('chunk_embeddings', $k, $emb) YIELD node, score
        MATCH (node)-[:MENTIONS]->(t:Threat)
        OPTIONAL MATCH (doc:Document)-[:HAS_CHUNK]->(node)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)
        OPTIONAL MATCH (p:Document)-[:SUPPORTS_RESPONSE_TO]->(t)
        OPTIONAL MATCH (t)-[:EXPLOITS]->(v:Vulnerability)
        OPTIONAL MATCH (t)-[:TARGETS]->(s:Service)
        RETURN node.id AS chunkId, node.text AS passage, node.source AS source, score,
               doc.id AS docId, t AS threat, collect(DISTINCT c) AS controls,
               collect(DISTINCT p) AS procs, collect(DISTINCT v) AS vulns, collect(DISTINCT s.name) AS targets
        ORDER BY score DESC
        """, k=k, emb=embed(question))
    if not hits:
        return None
    best = hits[0]
    t = best["threat"]
    ops = run("""
        MATCH (a:Alert)-[:INDICATES]->(:Threat {id:$t})
        OPTIONAL MATCH (u:User)-[:TRIGGERED]->(:Event)-[:CREATED_ALERT]->(a)
        OPTIONAL MATCH (a)-[:AFFECTS]->(s:Service)
        RETURN a.id AS alertId, a.severity AS severity, collect(DISTINCT u.id) AS users,
               collect(DISTINCT s.name) AS services ORDER BY a.id
        """, t=t["id"])
    alerts = [o["alertId"] for o in ops]
    users = sorted({u for o in ops for u in o["users"]})
    services = sorted({s for o in ops for s in o["services"]})

    detail = ""
    if alerts:
        detail = (f", linked to user(s) {_join(users)} " if users else ", with no individual user attributed ") \
                 + f"on service(s) {_join(services)}"
    observed = f"The graph holds {len(alerts)} alert(s) consistent with {t['name']}: {_join(alerts)}{detail}."
    interpretation = (f"Your question best matches the knowledge passage \"{best['passage']}\" "
                      f"(source: {best['source']}). This relates to {t['name']} ({t.get('referenceId')}), which may target "
                      f"{_join(best['targets'])}. Alerts linked to it are consistent with this threat, not proof of it.")
    response = (f"Controls that mitigate it: {_join([c['name'] for c in best['controls']])}. "
                f"Response procedure: {_join([p['id'] + ': ' + p['title'] for p in best['procs']])}. "
                f"{_join([p.get('text') for p in best['procs']])}")
    rels = [f"{best['chunkId']} MENTIONS {t['id']}"]
    rels += [f"{best['docId']} HAS_CHUNK {best['chunkId']}"] if best["docId"] else []
    rels += [f"{c['id']} MITIGATES {t['id']}" for c in best["controls"]]
    rels += [f"{p['id']} SUPPORTS_RESPONSE_TO {t['id']}" for p in best["procs"]]
    rels += [f"{t['id']} EXPLOITS {v['id']}" for v in best["vulns"]]
    rels += [f"{a} INDICATES {t['id']}" for a in alerts]
    nodes = [best["chunkId"], t["id"]] + [c["id"] for c in best["controls"]] + [p["id"] for p in best["procs"]] + alerts + users
    return dict(observed=observed, interpretation=interpretation, response=response,
                evidence=dict(nodes=nodes, relationships=rels,
                              sources=[best["source"]] + ([t["sourceUrl"]] if t.get("sourceUrl") else [])),
                retrievalMethod="vector_cypher", similarityScore=round(best["score"], 3),
                retrievedChunks=[{"chunk": h["chunkId"], "threat": h["threat"]["id"], "score": round(h["score"], 3)} for h in hits])


ALERT_ID = re.compile(r"alert[-\s]?(\d+)", re.I)
LATEST = re.compile(r"\b(latest|last|most recent|newest|this alert)\b", re.I)


def ask(question):
    m = ALERT_ID.search(question)
    alert_id = f"alert-{m.group(1)}" if m else None
    if not alert_id and LATEST.search(question) and "alert" in question.lower():
        rows = run("MATCH (a:Alert) RETURN a.id AS id ORDER BY toInteger(split(a.id,'-')[1]) DESC LIMIT 1")
        alert_id = rows[0]["id"] if rows else None
    out = route_a(alert_id) if alert_id else route_b(question)
    if out is None:
        return {"question": question, "answer": "The graph holds no evidence relevant to this question.",
                "evidence": {"nodes": [], "relationships": [], "sources": []}, "retrievalMethod": "none"}
    out["question"] = question
    out["answer"] = f"{out['observed']}\n\n{out['interpretation']}\n\n{out['response']}"
    return out

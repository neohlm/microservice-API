from .graph import run

HIGH = ["HIGH", "CRITICAL", "POSSIBLE_DOS"]


def alerts_for_service(service):
    """Q1: all alerts affecting a service (directly, or via events the service generated)."""
    return run("""
        MATCH (s:Service {name:$service})
        OPTIONAL MATCH (a1:Alert)-[:AFFECTS]->(s)
        OPTIONAL MATCH (:Event)-[:GENERATED_BY]->(s)<-[:GENERATED_BY]-(e:Event)-[:CREATED_ALERT]->(a2:Alert)
        WITH s, collect(DISTINCT a1) + collect(DISTINCT a2) AS al
        UNWIND al AS a
        WITH DISTINCT a WHERE a IS NOT NULL
        RETURN a.id AS alertId, a.ruleName AS rule, a.severity AS severity, a.status AS status,
               a.timestamp AS timestamp ORDER BY a.id
        """, service=service)


def users_high_severity():
    """Q2: users linked to high-severity alerts."""
    return run("""
        MATCH (u:User)-[:TRIGGERED]->(e:Event)-[:CREATED_ALERT]->(a:Alert)
        WHERE a.severity IN $high
        RETURN u.id AS user, collect(DISTINCT a.id) AS alerts, count(DISTINCT e) AS events
        ORDER BY events DESC
        """, high=HIGH)


def threats_for_service(service):
    """Q3: threats the alerts on a service are consistent with (INDICATES = may indicate)."""
    return run("""
        MATCH (a:Alert)-[:AFFECTS]->(:Service {name:$service})
        MATCH (a)-[:INDICATES]->(t:Threat)
        OPTIONAL MATCH (t)-[:EXPLOITS]->(v:Vulnerability)
        RETURN t.id AS threatId, t.name AS threat, t.referenceId AS reference,
               collect(DISTINCT v.id) AS vulnerabilities, collect(DISTINCT a.id) AS alerts
        """, service=service)


def controls_for_alert(alert_id):
    """Q4: controls and response procedures for an alert."""
    return run("""
        MATCH (a:Alert {id:$alertId})-[:INDICATES]->(t:Threat)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)
        OPTIONAL MATCH (d:Document)-[:SUPPORTS_RESPONSE_TO]->(t)
        RETURN t.name AS possibleThreat, collect(DISTINCT {id:c.id, name:c.name}) AS controls,
               collect(DISTINCT {id:d.id, title:d.title}) AS procedures
        """, alertId=alert_id)


def dependency_impact(service):
    """Q5: services that depend (directly or transitively) on a failing service, with their alerts."""
    return run("""
        MATCH (s:Service {name:$service})
        OPTIONAL MATCH p=(d:Service)-[:DEPENDS_ON*1..3]->(s)
        WITH s, d, min(length(p)) AS hops WHERE d IS NOT NULL
        OPTIONAL MATCH (a:Alert)-[:AFFECTS]->(d)
        RETURN d.name AS impactedService, hops, collect(DISTINCT a.id) AS alertsOnImpacted
        ORDER BY hops, impactedService
        """, service=service)


def alert_evidence(alert_id):
    """Route A (exact) retrieval: everything the graph knows about one alert."""
    return run("""
        MATCH (a:Alert {id:$alertId})
        OPTIONAL MATCH (e:Event)-[:CREATED_ALERT]->(a)
        OPTIONAL MATCH (u:User)-[:TRIGGERED]->(e)
        OPTIONAL MATCH (e)-[:GENERATED_BY]->(svc:Service)
        OPTIONAL MATCH (a)-[:INDICATES]->(t:Threat)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)
        OPTIONAL MATCH (d:Document)-[:SUPPORTS_RESPONSE_TO]->(t)
        RETURN a.id AS alertId, a.ruleName AS rule, a.severity AS severity, a.description AS description,
               collect(DISTINCT e.id) AS events, collect(DISTINCT u.id) AS users,
               collect(DISTINCT svc.name) AS services, t.id AS threatId, t.name AS possibleThreat,
               collect(DISTINCT {id:c.id, name:c.name}) AS controls,
               collect(DISTINCT {id:d.id, title:d.title}) AS procedures
        """, alertId=alert_id)

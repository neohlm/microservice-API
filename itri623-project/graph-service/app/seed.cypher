// ===== Reference knowledge (MITRE ATT&CK / CWE / OWASP API Top 10) =====
MERGE (t:Threat {id:'T-01'}) SET t.name='Password spraying', t.referenceId='T1110.003', t.source='MITRE ATT&CK', t.sourceUrl='https://attack.mitre.org/techniques/T1110/003/';
MERGE (v:Vulnerability {id:'CWE-307'}) SET v.name='Improper restriction of excessive authentication attempts', v.source='CWE', v.sourceUrl='https://cwe.mitre.org/data/definitions/307.html';
MERGE (c:Control {id:'C-01'}) SET c.name='Login throttling, account lockout and MFA';
MERGE (d:Document {id:'P-01'}) SET d.title='Investigate repeated login failures', d.revision=1, d.text='Check whether failures are spread across many accounts or concentrated on one, review the source IP addresses, confirm the time window, and look for any successful login that follows the failures. Reset credentials for any compromised account.';
MATCH (t:Threat {id:'T-01'}),(v:Vulnerability {id:'CWE-307'}),(c:Control {id:'C-01'}),(d:Document {id:'P-01'}) MERGE (t)-[:EXPLOITS]->(v) MERGE (c)-[:MITIGATES]->(t) MERGE (d)-[:DESCRIBES]->(c) MERGE (d)-[:SUPPORTS_RESPONSE_TO]->(t);

MERGE (t:Threat {id:'T-02'}) SET t.name='Broken object level authorization (object access abuse)', t.referenceId='API1:2023', t.source='OWASP API Security Top 10', t.sourceUrl='https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/';
MERGE (v:Vulnerability {id:'CWE-639'}) SET v.name='Authorization bypass through user-controlled key', v.source='CWE', v.sourceUrl='https://cwe.mitre.org/data/definitions/639.html';
MERGE (c:Control {id:'C-02'}) SET c.name='Server-side object-level authorization checks and role-based access control';
MERGE (d:Document {id:'P-02'}) SET d.title='Investigate unauthorised endpoint access', d.revision=1, d.text='Identify the user and role behind repeated forbidden requests, list the endpoints and object identifiers that were targeted, check whether any similar request succeeded, and verify that role checks are enforced on the server for every protected endpoint.';
MATCH (t:Threat {id:'T-02'}),(v:Vulnerability {id:'CWE-639'}),(c:Control {id:'C-02'}),(d:Document {id:'P-02'}) MERGE (t)-[:EXPLOITS]->(v) MERGE (c)-[:MITIGATES]->(t) MERGE (d)-[:DESCRIBES]->(c) MERGE (d)-[:SUPPORTS_RESPONSE_TO]->(t);

MERGE (t:Threat {id:'T-03'}) SET t.name='Unrestricted resource consumption (denial of service)', t.referenceId='API4:2023', t.source='OWASP API Security Top 10', t.sourceUrl='https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/';
MERGE (v:Vulnerability {id:'CWE-770'}) SET v.name='Allocation of resources without limits or throttling', v.source='CWE', v.sourceUrl='https://cwe.mitre.org/data/definitions/770.html';
MERGE (c:Control {id:'C-03'}) SET c.name='Gateway rate limiting, circuit breakers and resource quotas';
MERGE (d:Document {id:'P-03'}) SET d.title='Investigate abnormal request volume or service failure', d.revision=1, d.text='Identify which service is receiving a burst of requests or failing repeatedly, find the source of the traffic, check the health and dependencies of the affected service, apply rate limiting at the gateway and restart or scale the service if needed.';
MATCH (t:Threat {id:'T-03'}),(v:Vulnerability {id:'CWE-770'}),(c:Control {id:'C-03'}),(d:Document {id:'P-03'}) MERGE (t)-[:EXPLOITS]->(v) MERGE (c)-[:MITIGATES]->(t) MERGE (d)-[:DESCRIBES]->(c) MERGE (d)-[:SUPPORTS_RESPONSE_TO]->(t);

// ===== System topology (operational subgraph, static part) =====
UNWIND ['api-gateway','user-service','ticket-service','asset-service','soc-event-service','eureka-server'] AS n MERGE (:Service {name:n});
MATCH (g:Service {name:'api-gateway'}),(u:Service {name:'user-service'}),(t:Service {name:'ticket-service'}),(a:Service {name:'asset-service'}),(s:Service {name:'soc-event-service'})
MERGE (g)-[:DEPENDS_ON]->(u) MERGE (g)-[:DEPENDS_ON]->(t) MERGE (g)-[:DEPENDS_ON]->(a)
MERGE (t)-[:DEPENDS_ON]->(a) MERGE (u)-[:DEPENDS_ON]->(s) MERGE (t)-[:DEPENDS_ON]->(s) MERGE (g)-[:DEPENDS_ON]->(s);
MERGE (:Asset {id:'A-01', name:'User credentials and accounts'});
MERGE (:Asset {id:'A-02', name:'Helpdesk ticket data'});
MERGE (:Asset {id:'A-03', name:'IT asset register'});
MATCH (a1:Asset {id:'A-01'}),(a2:Asset {id:'A-02'}),(a3:Asset {id:'A-03'})
MERGE (e1:Endpoint {path:'/api/auth/login'}) MERGE (e2:Endpoint {path:'/api/users/{id}'}) MERGE (e3:Endpoint {path:'/api/tickets'}) MERGE (e4:Endpoint {path:'/api/assets/{id}'})
MERGE (e1)-[:EXPOSES]->(a1) MERGE (e2)-[:EXPOSES]->(a1) MERGE (e3)-[:EXPOSES]->(a2) MERGE (e4)-[:EXPOSES]->(a3);

// ===== Spec additions: roles, threat targets, service endpoints =====
MERGE (:Role {name:'ROLE_USER'});
MERGE (:Role {name:'ROLE_ADMIN'});
MATCH (r:Role {name:'ROLE_USER'}) MERGE (u:User {id:'drsmith'}) MERGE (u)-[:HAS_ROLE]->(r);
MATCH (t:Threat {id:'T-01'}),(s:Service {name:'user-service'}) MERGE (t)-[:TARGETS]->(s);
MATCH (t:Threat {id:'T-02'}),(s:Service {name:'user-service'}) MERGE (t)-[:TARGETS]->(s);
MATCH (t:Threat {id:'T-02'}),(s:Service {name:'ticket-service'}) MERGE (t)-[:TARGETS]->(s);
MATCH (t:Threat {id:'T-03'}),(s:Service {name:'api-gateway'}) MERGE (t)-[:TARGETS]->(s);
MATCH (t:Threat {id:'T-03'}),(s:Service {name:'ticket-service'}) MERGE (t)-[:TARGETS]->(s);
MATCH (t:Threat {id:'T-03'}),(s:Service {name:'asset-service'}) MERGE (t)-[:TARGETS]->(s);
MATCH (s:Service {name:'user-service'}),(e:Endpoint {path:'/api/auth/login'}) MERGE (s)-[:EXPOSES]->(e);
MATCH (s:Service {name:'user-service'}),(e:Endpoint {path:'/api/users/{id}'}) MERGE (s)-[:EXPOSES]->(e);
MATCH (s:Service {name:'ticket-service'}),(e:Endpoint {path:'/api/tickets'}) MERGE (s)-[:EXPOSES]->(e);
MATCH (s:Service {name:'asset-service'}),(e:Endpoint {path:'/api/assets/{id}'}) MERGE (s)-[:EXPOSES]->(e);

// ===== Text chunks for vector retrieval (paraphrased from MITRE ATT&CK, CWE and OWASP) =====
MERGE (k:Chunk {id:'CH-01a'}) SET k.text='Password spraying is a brute force technique where an adversary tries a few commonly used passwords against many accounts to avoid account lockouts. Repeated failed logins for one account or from one source address are typical indicators of a credential attack.', k.source='MITRE ATT&CK T1110.003';
MERGE (k:Chunk {id:'CH-01b'}) SET k.text='Mitigations for credential attacks include account lockout and login throttling, multi-factor authentication, a strong password policy and blocking abusive source IP addresses. Reset the password of any account that shows a successful login after repeated failures.', k.source='MITRE ATT&CK T1110.003';
MERGE (k:Chunk {id:'CH-02a'}) SET k.text='Broken object level authorization occurs when an API does not verify that the caller is allowed to access the requested object or endpoint. Repeated 403 forbidden responses for one user against protected endpoints suggest probing for unauthorised access.', k.source='OWASP API1:2023';
MERGE (k:Chunk {id:'CH-02b'}) SET k.text='Mitigate unauthorised access by enforcing role-based access control on the server for every endpoint, validating object ownership, and reviewing the audit log for requests that succeeded after the denied attempts.', k.source='OWASP API1:2023';
MERGE (k:Chunk {id:'CH-03a'}) SET k.text='Unrestricted resource consumption means an API accepts more requests or work than it can handle, causing slowdowns or denial of service. A sudden burst of requests to one service, or repeated downstream failures that open the circuit breaker, are indicators.', k.source='OWASP API4:2023';
MERGE (k:Chunk {id:'CH-03b'}) SET k.text='Mitigate resource exhaustion with rate limiting at the API gateway, circuit breakers with fallbacks, resource quotas, and by restarting or scaling the affected service. If a dependency fails, check dependent services for cascading impact.', k.source='OWASP API4:2023';
MATCH (d:Document {id:'P-01'}),(k:Chunk) WHERE k.id IN ['CH-01a','CH-01b'] MERGE (d)-[:HAS_CHUNK]->(k);
MATCH (d:Document {id:'P-02'}),(k:Chunk) WHERE k.id IN ['CH-02a','CH-02b'] MERGE (d)-[:HAS_CHUNK]->(k);
MATCH (d:Document {id:'P-03'}),(k:Chunk) WHERE k.id IN ['CH-03a','CH-03b'] MERGE (d)-[:HAS_CHUNK]->(k);
MATCH (t:Threat {id:'T-01'}),(k:Chunk) WHERE k.id IN ['CH-01a','CH-01b'] MERGE (k)-[:MENTIONS]->(t);
MATCH (t:Threat {id:'T-02'}),(k:Chunk) WHERE k.id IN ['CH-02a','CH-02b'] MERGE (k)-[:MENTIONS]->(t);
MATCH (t:Threat {id:'T-03'}),(k:Chunk) WHERE k.id IN ['CH-03a','CH-03b'] MERGE (k)-[:MENTIONS]->(t);
MATCH (c:Control {id:'C-01'}),(k:Chunk {id:'CH-01b'}) MERGE (k)-[:MENTIONS]->(c);
MATCH (c:Control {id:'C-02'}),(k:Chunk {id:'CH-02b'}) MERGE (k)-[:MENTIONS]->(c);
MATCH (c:Control {id:'C-03'}),(k:Chunk {id:'CH-03b'}) MERGE (k)-[:MENTIONS]->(c);

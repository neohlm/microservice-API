# ITRI623 Microservices Project — Service Desk System

Domain: IT Service Desk / Asset Management. Services: **Eureka Registry**, **API Gateway**
(Spring Cloud Gateway), **User Service** (also issues JWTs via `/api/auth/login`),
**Ticket Service**, **Asset Service**. Each service owns its own PostgreSQL database
(Database-per-Service pattern). Ticket Service calls Asset Service through Eureka
service discovery (`lb://asset-service`) wrapped in a Resilience4j circuit breaker.

## Prerequisites
- Java 17
- Maven 3.9+
- Docker + Docker Compose

## Running locally

```bash
# 1. Build all service JARs first (Docker images copy target/*.jar)
mvn clean package -DskipTests

# 2. Bring the whole system up
docker compose up --build
```

Then:
- Eureka dashboard: http://localhost:8761
- Gateway (single entry point): http://localhost:8080
- Swagger UI per service, e.g.: http://localhost:8081/swagger-ui.html

## Demo flow (matches the assignment's minimum demonstration scenario)

```bash
# 1. Login as the seeded user (Dr Smith) via the gateway
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"drsmith","password":"password123"}'

# 2. Create a ticket linked to the seeded "Research Server" asset (id=1)
curl -X POST http://localhost:8080/api/tickets \
  -H "Content-Type: application/json" \
  -d '{"description":"Cannot access research server","status":"OPEN","priority":"HIGH","requestedByUsername":"drsmith","assetId":1}'

# 3. Confirm routing: list tickets and assets through the gateway
curl http://localhost:8080/api/tickets
curl http://localhost:8080/api/assets
```

To demonstrate the circuit breaker: stop `asset-service`
(`docker compose stop asset-service`) and repeat step 2 — the Ticket Service falls
back gracefully instead of hanging or crashing.

## Project status (see ITRI623_Project_Plan.md for the full week-by-week plan)

- [x] Week 1 Day 1–2: scaffolding, Eureka, Gateway, 3 domain services, DB-per-service
- [ ] Week 1 Day 3–4: full CRUD polish, seed data (done for demo path above)
- [ ] Week 1 Day 5–7: JWT role restriction on delete endpoints, resilience testing
- [ ] Week 2: centralised logging/metrics, containerisation polish, API docs export,
      architecture diagram, demo video, technical report
- [ ] Phase 2 (Weeks 3–4): SOC event collection, detection rules, alerts, Neo4j, RAG

## Pushing to GitHub

```bash
git init
git add .
git commit -m "Initial scaffold: Eureka, Gateway, User/Ticket/Asset services, docker-compose"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

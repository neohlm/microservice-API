# Service Desk System

Domain: IT Service Desk / Asset Management. Services: **Eureka Registry**, **API Gateway** (Spring Cloud Gateway), **User Service** (also issues JWTs via `/api/auth/login`), **Ticket Service**, **Asset Service**. Each service owns its own PostgreSQL database (Database-per-Service pattern). Ticket Service calls Asset Service through Eureka service discovery (`lb://asset-service`) wrapped in a Resilience4j circuit breaker.

## Running locally

```bash
# 1. Build services
mvn clean package -DskipTests

# 2. Bring the whole system up
docker compose up --build
```

Then:
- Eureka dashboard: http://localhost:8761
- Gateway (single entry point): http://localhost:8090
- Swagger UI per service, e.g.: http://localhost:8081/swagger-ui.html

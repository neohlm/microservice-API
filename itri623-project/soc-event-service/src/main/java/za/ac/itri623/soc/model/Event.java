package za.ac.itri623.soc.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "soc_event")
public class Event {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime timestamp = LocalDateTime.now();

    @Column(nullable = false)
    private String serviceName;

    @Column(nullable = false)
    private String eventType; // e.g. AUTH_SUCCESS, AUTH_FAILURE, UNAUTHORISED_ACCESS, SERVICE_FAILURE, REQUEST_RECEIVED

    @Column(nullable = false)
    private String severity; // LOW, MEDIUM, HIGH

    private String userId;
    private String sourceIp;
    private String endpoint;
    private String httpMethod;
    private Integer statusCode;

    @Column(length = 1000)
    private String message;

    private String correlationId;
    private String affectedEntity;

    public Event() {}

    // Spec-shaped external id, derived from the DB id, e.g. "evt-42"
    public String getEventId() {
        return id == null ? null : "evt-" + id;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }
    public Integer getStatusCode() { return statusCode; }
    public void setStatusCode(Integer statusCode) { this.statusCode = statusCode; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getAffectedEntity() { return affectedEntity; }
    public void setAffectedEntity(String affectedEntity) { this.affectedEntity = affectedEntity; }
}

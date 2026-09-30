package za.ac.itri623.user.soc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Fire-and-forget client for soc-event-service. Emits a SOC event without
 * blocking or ever failing the caller's own request — if soc-event-service
 * is slow, unreachable, or down, the login/ticket/etc. request this is
 * called from must still succeed normally. Errors are logged, never thrown.
 */
@Component
public class SocEventClient {

    private static final Logger log = LoggerFactory.getLogger(SocEventClient.class);
    private final WebClient.Builder webClientBuilder;

    public SocEventClient(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public void emit(String serviceName, String eventType, String severity, String userId,
                      String sourceIp, String endpoint, String httpMethod, Integer statusCode,
                      String message, String affectedEntity) {
        Map<String, Object> event = new HashMap<>();
        event.put("serviceName", serviceName);
        event.put("eventType", eventType);
        event.put("severity", severity);
        event.put("userId", userId);
        event.put("sourceIp", sourceIp);
        event.put("endpoint", endpoint);
        event.put("httpMethod", httpMethod);
        event.put("statusCode", statusCode);
        event.put("message", message);
        event.put("affectedEntity", affectedEntity);
        event.put("correlationId", UUID.randomUUID().toString());

        webClientBuilder.build()
                .post()
                .uri("lb://soc-event-service/api/events")
                .bodyValue(event)
                .retrieve()
                .bodyToMono(Void.class)
                .onErrorResume(e -> {
                    log.warn("Failed to emit SOC event [{}]: {}", eventType, e.toString());
                    return Mono.empty();
                })
                .subscribe();
    }
}

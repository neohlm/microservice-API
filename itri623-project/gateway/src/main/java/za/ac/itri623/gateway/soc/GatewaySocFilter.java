package za.ac.itri623.gateway.soc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Emits a REQUEST_RECEIVED event (and a GATEWAY_ERROR for 5xx) for every proxied /api/ request. */
@Component
public class GatewaySocFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(GatewaySocFilter.class);
    private static final Pattern SUB = Pattern.compile("\"sub\"\\s*:\\s*\"([^\"]+)\"");

    private final WebClient.Builder builder;

    public GatewaySocFilter(WebClient.Builder socWebClientBuilder) {
        this.builder = socWebClientBuilder;
    }

    @Override
    public int getOrder() {
        return -1;   // run first so the doFinally fires after the whole chain, regardless of other filters
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (path.startsWith("/actuator")) {
            return chain.filter(exchange);
        }
        return chain.filter(exchange).doFinally(sig -> {
            Integer status = exchange.getResponse().getStatusCode() != null
                    ? exchange.getResponse().getStatusCode().value() : null;
            String ip = exchange.getRequest().getRemoteAddress() != null
                    ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : null;
            String user = userFromJwt(exchange.getRequest().getHeaders().getFirst("Authorization"));
            boolean serverError = status != null && status >= 500;
            emit(serverError ? "GATEWAY_ERROR" : "REQUEST_RECEIVED",
                    serverError ? "MEDIUM" : "LOW",
                    user, ip, path, exchange.getRequest().getMethod().name(), status,
                    serverError ? "Downstream returned a server error" : "Request routed through gateway");
        });
    }

    private String userFromJwt(String auth) {
        try {
            if (auth == null || !auth.startsWith("Bearer ")) return null;
            String[] parts = auth.substring(7).split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Matcher m = SUB.matcher(payload);
            return m.find() ? m.group(1) : null;   // display only, token is verified by the services
        } catch (Exception e) {
            return null;
        }
    }

    private void emit(String type, String severity, String user, String ip, String endpoint,
                      String method, Integer status, String message) {
        log.info("SOC gateway event {} {} {} -> {}", type, method, endpoint, status);
        Map<String, Object> ev = new HashMap<>();
        ev.put("serviceName", "api-gateway");
        ev.put("eventType", type);
        ev.put("severity", severity);
        ev.put("userId", user);
        ev.put("sourceIp", ip);
        ev.put("endpoint", endpoint);
        ev.put("httpMethod", method);
        ev.put("statusCode", status);
        ev.put("message", message);
        ev.put("affectedEntity", "api-gateway");
        ev.put("correlationId", UUID.randomUUID().toString());
        builder.build().post().uri("lb://soc-event-service/api/events")
                .bodyValue(ev).retrieve().bodyToMono(Void.class)
                .onErrorResume(e -> {
                    log.warn("Failed to emit gateway SOC event: {}", e.toString());
                    return Mono.empty();
                }).subscribe();
    }
}

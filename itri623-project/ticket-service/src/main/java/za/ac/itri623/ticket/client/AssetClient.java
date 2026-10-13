package za.ac.itri623.ticket.client;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import za.ac.itri623.ticket.soc.SocEventClient;

@Component
public class AssetClient {

    private static final Logger log = LoggerFactory.getLogger(AssetClient.class);

    private final WebClient.Builder webClientBuilder;

    private final SocEventClient soc;   // add the field, and add SocEventClient soc to the constructor

    public AssetClient(WebClient.Builder webClientBuilder, SocEventClient soc) {
        this.webClientBuilder = webClientBuilder;
        this.soc = soc;  // assign the parameter to the field
    }

    @CircuitBreaker(name = "assetService", fallbackMethod = "fallbackAsset")
    public AssetDto getAsset(Long assetId) {
        return webClientBuilder.build()
                .get()
                .uri("lb://asset-service/api/assets/{id}", assetId)
                .retrieve()
                .bodyToMono(AssetDto.class)
                .block();
    }

    public AssetDto fallbackAsset(Long assetId, Throwable t) {
        log.error("Asset Service call failed for assetId={}, falling back. Cause: {}", assetId, t.toString(), t);
        soc.emit("ticket-service", "SERVICE_FAILURE", "HIGH", null, null,
            "/api/assets/" + assetId, "GET", 503,
            "Asset Service unavailable, circuit breaker fallback used", "asset-service");
        AssetDto placeholder = new AssetDto();
        placeholder.setId(assetId);
        placeholder.setName("UNKNOWN (Asset Service unavailable)");
        placeholder.setStatus("UNVERIFIED");
        return placeholder;
    }

}

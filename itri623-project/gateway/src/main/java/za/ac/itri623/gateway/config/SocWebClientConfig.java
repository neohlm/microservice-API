package za.ac.itri623.gateway.config;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class SocWebClientConfig {

    @Bean
    @LoadBalanced
    public WebClient.Builder socWebClientBuilder() {
        return WebClient.builder();
    }
}

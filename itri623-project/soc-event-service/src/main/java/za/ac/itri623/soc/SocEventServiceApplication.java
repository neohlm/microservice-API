package za.ac.itri623.soc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SocEventServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SocEventServiceApplication.class, args);
    }
}

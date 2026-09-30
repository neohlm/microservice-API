package za.ac.itri623.soc.repository;

import za.ac.itri623.soc.model.Event;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.List;

public interface EventRepository extends JpaRepository<Event, Long> {
    List<Event> findByServiceName(String serviceName);
    List<Event> findBySeverity(String severity);
    List<Event> findByEventTypeAndUserIdAndTimestampAfter(String eventType, String userId, LocalDateTime after);
    List<Event> findByEventTypeAndSourceIpAndTimestampAfter(String eventType, String sourceIp, LocalDateTime after);
    List<Event> findByEventTypeAndServiceNameAndTimestampAfter(String eventType, String serviceName, LocalDateTime after);
}

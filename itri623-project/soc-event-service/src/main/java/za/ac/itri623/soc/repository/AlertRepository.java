package za.ac.itri623.soc.repository;

import za.ac.itri623.soc.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    List<Alert> findBySeverity(String severity);
    List<Alert> findByStatus(String status);
    List<Alert> findByAffectedService(String affectedService);

    // Used to avoid raising the same alert repeatedly on every scheduler run.
    boolean existsByRuleNameAndAffectedUserAndAffectedServiceAndTimestampAfter(
            String ruleName, String affectedUser, String affectedService, LocalDateTime after);
}

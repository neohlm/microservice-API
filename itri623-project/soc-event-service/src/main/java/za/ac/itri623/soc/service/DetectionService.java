package za.ac.itri623.soc.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import za.ac.itri623.soc.model.Alert;
import za.ac.itri623.soc.model.Event;
import za.ac.itri623.soc.repository.AlertRepository;
import za.ac.itri623.soc.repository.EventRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Detection rules. Each rule reads recent events from the SOC event store,
 * applies a threshold, and raises an Alert that lists the events that
 * triggered it (relatedEvents) so every alert is traceable to its evidence.
 */
@Service
public class DetectionService {

    private static final Logger log = LoggerFactory.getLogger(DetectionService.class);

    private final EventRepository eventRepository;
    private final AlertRepository alertRepository;

    @Value("${soc.rules.window-minutes:5}")
    private int windowMinutes;
    @Value("${soc.rules.failed-login-threshold:5}")
    private int failedLoginThreshold;
    @Value("${soc.rules.unauthorised-threshold:3}")
    private int unauthorisedThreshold;
    @Value("${soc.rules.request-rate-threshold:30}")
    private int requestRateThreshold;
    @Value("${soc.rules.request-rate-window-seconds:60}")
    private int requestRateWindowSeconds;
    @Value("${soc.rules.service-failure-threshold:3}")
    private int serviceFailureThreshold;

    public DetectionService(EventRepository eventRepository, AlertRepository alertRepository) {
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
    }

    @Scheduled(fixedDelayString = "${soc.rules.interval-ms:15000}", initialDelay = 20000)
    public void scheduledRun() {
        try {
            evaluate();
        } catch (Exception e) {
            log.warn("Detection run failed: {}", e.toString());
        }
    }

    /** Runs all rules once. Returns the number of NEW alerts raised. */
    public int evaluate() {
        int created = 0;
        created += ruleMultipleFailedLogins();
        created += ruleUnauthorisedAccess();
        created += ruleAbnormalRequestRate();
        created += ruleServiceFailure();
        if (created > 0) {
            log.info("Detection run raised {} new alert(s)", created);
        }
        return created;
    }

    // Rule 1 - same user, >= N AUTH_FAILURE events inside the window -> HIGH
    private int ruleMultipleFailedLogins() {
        LocalDateTime since = LocalDateTime.now().minusMinutes(windowMinutes);
        Map<String, List<Event>> byUser = eventRepository
                .findByEventTypeAndTimestampAfter("AUTH_FAILURE", since).stream()
                .filter(e -> e.getUserId() != null)
                .collect(Collectors.groupingBy(Event::getUserId));
        int created = 0;
        for (Map.Entry<String, List<Event>> entry : byUser.entrySet()) {
            List<Event> events = entry.getValue();
            if (events.size() >= failedLoginThreshold) {
                boolean made = raise("Multiple Failed Logins", "HIGH",
                        events.size() + " failed login attempts for user '" + entry.getKey()
                                + "' within " + windowMinutes + " minutes.",
                        events, "user-service", entry.getKey(), "login-endpoint",
                        "Temporarily lock or throttle the account and verify whether it is being targeted or compromised.");
                if (made) created++;
            }
        }
        return created;
    }

    // Rule 2 - same user, >= N UNAUTHORISED_ACCESS (401/403) events inside the window
    private int ruleUnauthorisedAccess() {
        LocalDateTime since = LocalDateTime.now().minusMinutes(windowMinutes);
        Map<String, List<Event>> byUser = eventRepository
                .findByEventTypeAndTimestampAfter("UNAUTHORISED_ACCESS", since).stream()
                .filter(e -> e.getUserId() != null)
                .collect(Collectors.groupingBy(Event::getUserId));
        int created = 0;
        for (Map.Entry<String, List<Event>> entry : byUser.entrySet()) {
            List<Event> events = entry.getValue();
            if (events.size() >= unauthorisedThreshold) {
                String severity = events.size() >= unauthorisedThreshold + 2 ? "HIGH" : "MEDIUM";
                String endpoint = events.get(events.size() - 1).getEndpoint();
                boolean made = raise("Unauthorised Endpoint Access", severity,
                        "User '" + entry.getKey() + "' was denied access to protected endpoints "
                                + events.size() + " times within " + windowMinutes + " minutes.",
                        events, events.get(0).getServiceName(), entry.getKey(), endpoint,
                        "Review the user's role and recent activity; confirm whether the access attempts are legitimate.");
                if (made) created++;
            }
        }
        return created;
    }

    // Rule 3 - one service receives > N REQUEST_RECEIVED events in a short window -> POSSIBLE_DOS
    private int ruleAbnormalRequestRate() {
        LocalDateTime since = LocalDateTime.now().minusSeconds(requestRateWindowSeconds);
        Map<String, List<Event>> byService = eventRepository
                .findByEventTypeAndTimestampAfter("REQUEST_RECEIVED", since).stream()
                .filter(e -> e.getServiceName() != null)
                .collect(Collectors.groupingBy(Event::getServiceName));
        int created = 0;
        for (Map.Entry<String, List<Event>> entry : byService.entrySet()) {
            List<Event> events = entry.getValue();
            if (events.size() > requestRateThreshold) {
                boolean made = raise("Abnormal Request Rate", "POSSIBLE_DOS",
                        entry.getKey() + " received " + events.size() + " requests in "
                                + requestRateWindowSeconds + " seconds (threshold " + requestRateThreshold + ").",
                        events, entry.getKey(), null, entry.getKey(),
                        "Apply rate limiting at the gateway and identify the source of the traffic.");
                if (made) created++;
            }
        }
        return created;
    }

    // Rule 4 - the same downstream service fails >= N times (circuit breaker fallbacks) -> HIGH
    private int ruleServiceFailure() {
        LocalDateTime since = LocalDateTime.now().minusMinutes(windowMinutes);
        Map<String, List<Event>> byTarget = eventRepository
                .findByEventTypeAndTimestampAfter("SERVICE_FAILURE", since).stream()
                .filter(e -> e.getAffectedEntity() != null)
                .collect(Collectors.groupingBy(Event::getAffectedEntity));
        int created = 0;
        for (Map.Entry<String, List<Event>> entry : byTarget.entrySet()) {
            List<Event> events = entry.getValue();
            if (events.size() >= serviceFailureThreshold) {
                boolean made = raise("Service Failure", "HIGH",
                        entry.getKey() + " failed " + events.size() + " times within " + windowMinutes
                                + " minutes (calls from " + events.get(0).getServiceName() + ").",
                        events, entry.getKey(), null, entry.getKey(),
                        "Check the health of " + entry.getKey() + ", restart it if needed, and review dependent services.");
                if (made) created++;
            }
        }
        return created;
    }

    // Creates the alert unless an equivalent one was already raised inside the window.
    private boolean raise(String ruleName, String severity, String description, List<Event> related,
                          String affectedService, String affectedUser, String affectedEntity, String action) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(windowMinutes);
        if (alertRepository.existsByRuleNameAndAffectedUserAndAffectedServiceAndTimestampAfter(
                ruleName, affectedUser, affectedService, since)) {
            return false;
        }
        Alert alert = new Alert();
        alert.setRuleName(ruleName);
        alert.setSeverity(severity);
        alert.setDescription(description);
        alert.setRelatedEvents(related.stream().map(Event::getEventId).collect(Collectors.toList()));
        alert.setAffectedService(affectedService);
        alert.setAffectedUser(affectedUser);
        alert.setAffectedEntity(affectedEntity);
        alert.setRecommendedAction(action);
        alertRepository.save(alert);
        return true;
    }
}

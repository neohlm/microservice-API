package za.ac.itri623.soc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import za.ac.itri623.soc.model.Alert;
import za.ac.itri623.soc.repository.AlertRepository;
import za.ac.itri623.soc.service.DetectionService;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertRepository alertRepository;
    private final DetectionService detectionService;

    public AlertController(AlertRepository alertRepository, DetectionService detectionService) {
        this.alertRepository = alertRepository;
        this.detectionService = detectionService;
    }

    @GetMapping
    public List<Alert> getAll(@RequestParam(required = false) String severity,
                              @RequestParam(required = false) String status,
                              @RequestParam(required = false) String service) {
        if (severity != null) return alertRepository.findBySeverity(severity);
        if (status != null) return alertRepository.findByStatus(status);
        if (service != null) return alertRepository.findByAffectedService(service);
        return alertRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Alert> getById(@PathVariable Long id) {
        return alertRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // Lets an analyst move an alert through OPEN -> ACKNOWLEDGED -> RESOLVED.
    @PutMapping("/{id}/status")
    public ResponseEntity<Alert> updateStatus(@PathVariable Long id, @RequestParam String value) {
        return alertRepository.findById(id)
                .map(a -> {
                    a.setStatus(value);
                    return ResponseEntity.ok(alertRepository.save(a));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // Runs every rule immediately instead of waiting for the scheduler. Handy for demos.
    @PostMapping("/evaluate")
    public Map<String, Integer> evaluate() {
        return Map.of("newAlerts", detectionService.evaluate());
    }
}

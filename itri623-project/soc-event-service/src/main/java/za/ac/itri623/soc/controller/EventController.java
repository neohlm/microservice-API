package za.ac.itri623.soc.controller;

import za.ac.itri623.soc.model.Event;
import za.ac.itri623.soc.repository.EventRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/events")
public class EventController {

    private final EventRepository eventRepository;

    public EventController(EventRepository eventRepository) {
        this.eventRepository = eventRepository;
    }

    // Called by other services (fire-and-forget) whenever a security- or
    // operational-relevant condition occurs. Deliberately tolerant: only
    // serviceName and eventType are required, everything else is optional.
    @PostMapping
    public ResponseEntity<Event> create(@RequestBody Event event) {
        event.setId(null); // ignore any id the caller might send
        Event saved = eventRepository.save(event);
        return ResponseEntity.ok(saved);
    }

    // Supports the SOC storage requirement: view, and filter by service or severity.
    @GetMapping
    public List<Event> getAll(
            @RequestParam(required = false) String service,
            @RequestParam(required = false) String severity) {
        if (service != null) {
            return eventRepository.findByServiceName(service);
        }
        if (severity != null) {
            return eventRepository.findBySeverity(severity);
        }
        return eventRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Event> getById(@PathVariable Long id) {
        return eventRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}

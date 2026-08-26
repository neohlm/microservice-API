package za.ac.itri623.ticket.controller;

import za.ac.itri623.ticket.client.AssetClient;
import za.ac.itri623.ticket.client.AssetDto;
import za.ac.itri623.ticket.model.Ticket;
import za.ac.itri623.ticket.repository.TicketRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/tickets")
public class TicketController {

    private final TicketRepository ticketRepository;
    private final AssetClient assetClient;

    public TicketController(TicketRepository ticketRepository, AssetClient assetClient) {
        this.ticketRepository = ticketRepository;
        this.assetClient = assetClient;
    }

    @GetMapping
    public List<Ticket> getAll() {
        return ticketRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Ticket> getById(@PathVariable Long id) {
        return ticketRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // Ticket-to-Asset cross-service check: validates the asset exists via Asset Service
    // before persisting, then returns the enriched view — this is the "meaningful
    // interaction between services" required by the spec, and exercises the circuit breaker.
    @PostMapping
    public ResponseEntity<?> create(@RequestBody Ticket ticket) {
        AssetDto asset = assetClient.getAsset(ticket.getAssetId());
        if (asset == null) {
            return ResponseEntity.badRequest().body("Referenced asset not found");
        }
        Ticket saved = ticketRepository.save(ticket);
        return ResponseEntity.ok(Map.of(
                "ticket", saved,
                "linkedAsset", asset
        ));
    }

    @PutMapping("/{id}")
    public ResponseEntity<Ticket> update(@PathVariable Long id, @RequestBody Ticket updated) {
        return ticketRepository.findById(id)
                .map(existing -> {
                    existing.setDescription(updated.getDescription());
                    existing.setStatus(updated.getStatus());
                    existing.setPriority(updated.getPriority());
                    return ResponseEntity.ok(ticketRepository.save(existing));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        if (!ticketRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        ticketRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}

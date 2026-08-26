-- Seed data matching the spec's own example. asset_id=1 corresponds to
-- 'Research Server' seeded in asset-service.
INSERT INTO ticket (description, status, priority, requested_by_username, asset_id, created_at)
SELECT 'Cannot access research server', 'OPEN', 'HIGH', 'drsmith', 1, now()
WHERE NOT EXISTS (SELECT 1 FROM ticket WHERE description = 'Cannot access research server');

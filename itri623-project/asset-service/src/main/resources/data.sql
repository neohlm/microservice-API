-- Seed data matching the spec's own example.
INSERT INTO asset (name, type, department, status)
SELECT 'Research Server', 'SERVER', 'Computer Science', 'ACTIVE'
WHERE NOT EXISTS (SELECT 1 FROM asset WHERE name = 'Research Server');

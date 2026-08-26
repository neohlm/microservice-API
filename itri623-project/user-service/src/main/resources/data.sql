-- Seed users matching the spec's own example data.
-- Both passwords below are BCrypt hashes of the plaintext 'password123' — verified hash, for demo purposes only.
INSERT INTO app_user (username, password, full_name, department, role)
SELECT 'drsmith', '$2b$10$rlCgoDj1mqYuoDF4Tj/E9u13y9aV2rZtxM53LIFPt4P2ZxLH/XXUy', 'Dr Smith', 'Computer Science', 'USER'
WHERE NOT EXISTS (SELECT 1 FROM app_user WHERE username = 'drsmith');

INSERT INTO app_user (username, password, full_name, department, role)
SELECT 'admin', '$2b$10$rlCgoDj1mqYuoDF4Tj/E9u13y9aV2rZtxM53LIFPt4P2ZxLH/XXUy', 'System Admin', 'IT Services', 'ADMIN'
WHERE NOT EXISTS (SELECT 1 FROM app_user WHERE username = 'admin');

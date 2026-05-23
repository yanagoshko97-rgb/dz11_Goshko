DROP TABLE IF EXISTS integrity_checks;

CREATE TABLE integrity_checks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    component_id VARCHAR(100),
    component_type VARCHAR(100),
    content TEXT,
    reference_content TEXT,
    current_hash VARCHAR(128),
    reference_hash VARCHAR(128),
    status VARCHAR(50),
    checked_at DATETIME
);
-- A executer une seule fois dans supervision_db pour creer la table d'historique
-- Commande : docker exec -i mysql mysql -uroot -proot supervision_db < create_anomalies_history.sql

CREATE TABLE IF NOT EXISTS anomalies_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metric VARCHAR(50) NOT NULL,
    container VARCHAR(100) NOT NULL,
    value VARCHAR(100),
    reason VARCHAR(255),
    severity VARCHAR(20),
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL
);

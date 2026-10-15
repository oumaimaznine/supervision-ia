from auth import get_db_connection

def save_anomaly(metric, container, value, reason, severity):
    """Enregistre une anomalie detectee dans l'historique (uniquement si anomaly=True)."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO anomalies_history (metric, container, value, reason, severity)
                   VALUES (%s, %s, %s, %s, %s)""",
                (metric, container, str(value), reason, severity)
            )
        conn.commit()
    finally:
        conn.close()

def save_all_anomalies(results):
    """Parcourt les resultats de run_all_checks() et enregistre uniquement ceux qui sont anomaly=True.
    Evite les doublons en ne sauvegardant pas une anomalie deja enregistree comme non-resolue
    pour le meme container+metric dans les 5 dernieres minutes."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for r in results:
                if not r.get("anomaly"):
                    continue

                cursor.execute(
                    """SELECT id FROM anomalies_history
                       WHERE metric = %s AND container = %s AND resolved = FALSE
                       AND detected_at >= NOW() - INTERVAL 5 MINUTE
                       ORDER BY detected_at DESC LIMIT 1""",
                    (r["metric"], r["container"])
                )
                existing = cursor.fetchone()
                if existing:
                    continue  # deja enregistree recemment, on evite le doublon

                cursor.execute(
                    """INSERT INTO anomalies_history (metric, container, value, reason, severity)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (r["metric"], r["container"], str(r["value"]), r["reason"], r["severity"])
                )
        conn.commit()
    finally:
        conn.close()

def get_anomalies_history(limit=100, container=None):
    """Retourne l'historique des anomalies, les plus recentes d'abord."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if container:
                cursor.execute(
                    """SELECT * FROM anomalies_history
                       WHERE container = %s
                       ORDER BY detected_at DESC LIMIT %s""",
                    (container, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM anomalies_history ORDER BY detected_at DESC LIMIT %s",
                    (limit,)
                )
            rows = cursor.fetchall()
            # convertir les dates en texte pour un envoi JSON propre
            for row in rows:
                if row.get("detected_at"):
                    row["detected_at"] = row["detected_at"].strftime("%Y-%m-%d %H:%M:%S")
                if row.get("resolved_at"):
                    row["resolved_at"] = row["resolved_at"].strftime("%Y-%m-%d %H:%M:%S")
            return rows
    finally:
        conn.close()

def get_anomaly_stats(hours=24):
    """Statistiques simples sur les X dernieres heures (pour les rapports plus tard)."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT COUNT(*) as total, severity FROM anomalies_history
                   WHERE detected_at >= NOW() - INTERVAL %s HOUR
                   GROUP BY severity""",
                (hours,)
            )
            return cursor.fetchall()
    finally:
        conn.close()

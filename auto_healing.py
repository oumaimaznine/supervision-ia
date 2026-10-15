import time
from auth import get_db_connection

MANAGED_CONTAINERS = {
    "prometheus", "grafana", "node-exporter", "cadvisor",
    "stress-test", "mysql", "phpmyadmin", "gestion-academique",
}

COOLDOWN_SECONDS = 120
_last_action_time = {}

auto_healing_state = {"enabled": True}


def is_in_cooldown(container):
    last = _last_action_time.get(container)
    if last is None:
        return False
    return (time.time() - last) < COOLDOWN_SECONDS


def log_action(container, metric, reason, action, success, details=""):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO healing_actions (container, metric, reason, action, success, details)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (container, metric, reason, action, success, details)
            )
        conn.commit()
    finally:
        conn.close()


def restart_container(docker_client, container_name):
    try:
        container = docker_client.containers.get(container_name)
        container.restart(timeout=10)
        return True, "Conteneur redemarre avec succes"
    except Exception as e:
        return False, str(e)


def decide_action(anomaly):
    metric = anomaly.get("metric")
    container = anomaly.get("container")

    if container not in MANAGED_CONTAINERS:
        return None

    if metric == "Container Status":
        return "restart"
    if metric == "Restart Count":
        return None
    if metric in ("CPU", "RAM") and anomaly.get("severity") == "High":
        return "restart"

    return None


def auto_heal(docker_client, anomaly_results):
    if not auto_healing_state["enabled"]:
        return []

    actions_taken = []

    for anomaly in anomaly_results:
        if not anomaly.get("anomaly"):
            continue

        container = anomaly.get("container")
        action = decide_action(anomaly)

        if action is None:
            continue
        if is_in_cooldown(container):
            continue

        if action == "restart":
            success, details = restart_container(docker_client, container)
            _last_action_time[container] = time.time()

            log_action(
                container=container,
                metric=anomaly.get("metric"),
                reason=anomaly.get("reason"),
                action="restart",
                success=success,
                details=details,
            )

            actions_taken.append({
                "container": container,
                "metric": anomaly.get("metric"),
                "action": "restart",
                "success": success,
                "details": details,
            })

    return actions_taken


def get_healing_actions(limit=100):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM healing_actions ORDER BY triggered_at DESC LIMIT %s",
                (limit,)
            )
            rows = cursor.fetchall()
            for row in rows:
                if row.get("triggered_at"):
                    row["triggered_at"] = row["triggered_at"].strftime("%Y-%m-%d %H:%M:%S")
            return rows
    finally:
        conn.close()


def get_healing_stats():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as total_actions FROM healing_actions")
            total = cursor.fetchone()

            cursor.execute(
                "SELECT COUNT(*) as restarts_last_24h FROM healing_actions WHERE triggered_at >= NOW() - INTERVAL 24 HOUR"
            )
            last_24h = cursor.fetchone()

            return {
                "total_actions": total["total_actions"],
                "actions_last_24h": last_24h["restarts_last_24h"],
                "auto_healing_enabled": auto_healing_state["enabled"],
            }
    finally:
        conn.close()
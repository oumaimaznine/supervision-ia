import requests
import docker
import pandas as pd
from sklearn.ensemble import IsolationForest

PROMETHEUS_URL = "http://localhost:9090"

def get_container_name(container_id_path, docker_client):
    """Convertit un id cAdvisor (ex: /docker/abc123...) en nom reel du conteneur."""
    try:
        short_id = container_id_path.replace("/docker/", "")
        container = docker_client.containers.get(short_id)
        return container.name
    except Exception:
        return None

def query_prometheus_instant(query):
    """Fait une requete instantanee (valeur actuelle) a Prometheus."""
    response = requests.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query})
    return response.json()["data"]["result"]

def get_prometheus_now():
    """Demande a Prometheus l'heure qu'il pense qu'il est."""
    data = query_prometheus_instant("time()")
    return float(data[0]) if data else None

def query_prometheus_range_multi(query, duration_minutes=10, step_seconds=15, label_key="id"):
    """Recupere l'historique d'une metrique pour PLUSIEURS series (ex: un conteneur par serie).
    Retourne un dict {valeur_du_label: DataFrame}."""
    end_time = get_prometheus_now()
    if end_time is None:
        return {}

    start_time = end_time - (duration_minutes * 60)
    params = {
        "query": query,
        "start": int(start_time),
        "end": int(end_time),
        "step": f"{step_seconds}s"
    }
    response = requests.get(f"{PROMETHEUS_URL}/api/v1/query_range", params=params)
    data = response.json()["data"]["result"]

    series_dict = {}
    for entry in data:
        label_value = entry["metric"].get(label_key, "unknown")
        values = entry["values"]
        df = pd.DataFrame(values, columns=["timestamp", "value"])
        df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
        df["value"] = df["value"].astype(float)
        series_dict[label_value] = df

    return series_dict

def get_container_memory_limit_bytes():
    """Recupere la limite memoire de chaque conteneur (pour calculer un %)."""
    data = query_prometheus_instant("container_spec_memory_limit_bytes")
    limits = {}
    for entry in data:
        container_id = entry["metric"].get("id", "")
        limit = float(entry["value"][1])
        if limit > 0:
            limits[container_id] = limit
    return limits

def detect_anomaly_ai(df, min_value_threshold=0):
    """Fonction generique : entraine Isolation Forest sur l'historique, verifie si la DERNIERE valeur est anormale.
    Retourne (is_anomaly, last_value)."""
    if len(df) < 5:
        return False, None

    model = IsolationForest(contamination=0.1, random_state=42)
    df = df.copy()
    df["anomaly_score"] = model.fit_predict(df[["value"]])

    last_row = df.iloc[-1]
    statistically_unusual = last_row["anomaly_score"] == -1
    value_significant = last_row["value"] > min_value_threshold

    is_anomaly = statistically_unusual and value_significant
    return is_anomaly, round(last_row["value"], 2)

def check_cpu_anomalies_ai(docker_client, duration_minutes=10):
    """Detecte les anomalies CPU par conteneur via Isolation Forest."""
    results = []
    series = query_prometheus_range_multi(
        'rate(container_cpu_usage_seconds_total[1m]) * 100',
        duration_minutes=duration_minutes
    )

    for container_id, df in series.items():
        name = get_container_name(container_id, docker_client)
        if name is None:
            continue

        is_anomaly, value = detect_anomaly_ai(df, min_value_threshold=15)
        if value is None:
            continue

        results.append({
            "metric": "CPU",
            "container": name,
            "value": value,
            "threshold": "AI-based (Isolation Forest)",
            "anomaly": bool(is_anomaly),
            "reason": "Unusual CPU behavior detected" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

def check_ram_anomalies_ai(docker_client, duration_minutes=10):
    """Detecte les anomalies RAM par conteneur via Isolation Forest."""
    results = []
    series = query_prometheus_range_multi(
        'container_memory_usage_bytes',
        duration_minutes=duration_minutes
    )

    for container_id, df in series.items():
        name = get_container_name(container_id, docker_client)
        if name is None:
            continue

        df = df.copy()
        df["value"] = df["value"] / (1024 * 1024)

        is_anomaly, value = detect_anomaly_ai(df, min_value_threshold=0)
        if value is None:
            continue

        results.append({
            "metric": "RAM",
            "container": name,
            "value": f"{value} MB",
            "threshold": "AI-based (Isolation Forest)",
            "anomaly": bool(is_anomaly),
            "reason": "Unusual memory behavior detected" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

def check_system_cpu_ai(duration_minutes=10):
    """Detecte un comportement CPU systeme anormal via Isolation Forest."""
    results = []
    query = '100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)'
    series = query_prometheus_range_multi(query, duration_minutes=duration_minutes, label_key="job")

    for _, df in series.items():
        is_anomaly, value = detect_anomaly_ai(df, min_value_threshold=15)
        if value is None:
            continue

        results.append({
            "metric": "CPU",
            "container": "system",
            "value": value,
            "threshold": "AI-based (Isolation Forest)",
            "anomaly": bool(is_anomaly),
            "reason": "Unusual system CPU behavior detected" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

def check_system_ram_ai(duration_minutes=10):
    """Detecte un comportement RAM systeme anormal via Isolation Forest."""
    results = []
    query = '100 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100)'
    series = query_prometheus_range_multi(query, duration_minutes=duration_minutes, label_key="job")

    for _, df in series.items():
        is_anomaly, value = detect_anomaly_ai(df, min_value_threshold=0)
        if value is None:
            continue

        results.append({
            "metric": "RAM",
            "container": "system",
            "value": f"{value}%",
            "threshold": "AI-based (Isolation Forest)",
            "anomaly": bool(is_anomaly),
            "reason": "Unusual system memory behavior detected" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

def check_disk_space_ai(duration_minutes=10):
    """Detecte un comportement disque anormal via Isolation Forest, par point de montage."""
    results = []
    query = '100 - (node_filesystem_avail_bytes{fstype!="tmpfs"} / node_filesystem_size_bytes{fstype!="tmpfs"} * 100)'
    series = query_prometheus_range_multi(query, duration_minutes=duration_minutes, label_key="mountpoint")

    for mountpoint, df in series.items():
        is_anomaly, value = detect_anomaly_ai(df, min_value_threshold=0)
        if value is None:
            continue

        results.append({
            "metric": "Disk",
            "container": f"system ({mountpoint})",
            "value": f"{value}%",
            "threshold": "AI-based (Isolation Forest)",
            "anomaly": bool(is_anomaly),
            "reason": "Unusual disk usage behavior detected" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

def check_stopped_containers(docker_client):
    """Verifie si des conteneurs sont arretes (regle binaire, volontairement non-IA)."""
    results = []
    all_containers = docker_client.containers.list(all=True)

    for container in all_containers:
        status = container.status
        if status != "running":
            results.append({
                "metric": "Container Status",
                "container": container.name,
                "value": status,
                "threshold": "running",
                "anomaly": True,
                "reason": f"Container is not running (status: {status})",
                "severity": "High"
            })

    return results

def check_crash_loop(docker_client, restart_threshold=3):
    """Verifie si un conteneur redemarre en boucle (regle binaire, volontairement non-IA)."""
    results = []
    all_containers = docker_client.containers.list(all=True)

    for container in all_containers:
        restart_count = container.attrs.get("RestartCount", 0)
        is_anomaly = restart_count >= restart_threshold

        results.append({
            "metric": "Restart Count",
            "container": container.name,
            "value": restart_count,
            "threshold": restart_threshold,
            "anomaly": is_anomaly,
            "reason": "Container is crash-looping" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

def check_memory_leak(duration_minutes=20, min_increase_percent=10):
    """Detecte une possible fuite memoire : tendance decroissante de la RAM disponible."""
    results = []
    query = 'node_memory_MemAvailable_bytes'
    series = query_prometheus_range_multi(query, duration_minutes=duration_minutes, label_key="job")

    for _, df in series.items():
        if len(df) < 5:
            continue

        first_value = df["value"].iloc[0]
        last_value = df["value"].iloc[-1]
        decrease_percent = ((first_value - last_value) / first_value) * 100 if first_value > 0 else 0
        is_consistently_decreasing = (df["value"].diff().dropna() <= 0).mean() > 0.7

        is_anomaly = decrease_percent > min_increase_percent and is_consistently_decreasing

        results.append({
            "metric": "Memory Leak",
            "container": "system",
            "value": f"-{round(decrease_percent, 2)}% available RAM over {duration_minutes}min",
            "threshold": f"{min_increase_percent}% sustained decrease",
            "anomaly": bool(is_anomaly),
            "reason": "Possible memory leak: available RAM steadily decreasing" if is_anomaly else "Normal",
            "severity": "High" if is_anomaly else "Low"
        })

    return results

if __name__ == "__main__":
    client = docker.from_env()

    print("=== CPU conteneurs (IA) ===")
    for r in check_cpu_anomalies_ai(client):
        print(r)

    print("\n=== RAM conteneurs (IA) ===")
    for r in check_ram_anomalies_ai(client):
        print(r)

    print("\n=== CPU systeme (IA) ===")
    for r in check_system_cpu_ai():
        print(r)

    print("\n=== RAM systeme (IA) ===")
    for r in check_system_ram_ai():
        print(r)

    print("\n=== Disque (IA) ===")
    for r in check_disk_space_ai():
        print(r)

    print("\n=== Conteneurs arretes ===")
    for r in check_stopped_containers(client):
        print(r)

    print("\n=== Crash loop ===")
    for r in check_crash_loop(client):
        print(r)

    print("\n=== Fuite memoire ===")
    for r in check_memory_leak():
        print(r)

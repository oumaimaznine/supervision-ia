import requests
import pandas as pd
from sklearn.ensemble import IsolationForest

PROMETHEUS_URL = "http://localhost:9090"

def get_prometheus_time():
    """Demande a Prometheus l'heure qu'il pense qu'il est (evite les decalages d'horloge Windows)."""
    response = requests.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": "time()"})
    data = response.json()
    return float(data["data"]["result"][0])

def get_metric_data(metric_name, duration_minutes=60, step_seconds=15):
    """Recupere l'historique d'une metrique et la transforme en DataFrame pandas."""
    end_time = get_prometheus_time()
    start_time = end_time - (duration_minutes * 60)

    params = {
        "query": metric_name,
        "start": int(start_time),
        "end": int(end_time),
        "step": f"{step_seconds}s"
    }

    response = requests.get(f"{PROMETHEUS_URL}/api/v1/query_range", params=params)
    data = response.json()

    results = data["data"]["result"]

    if len(results) == 0:
        return pd.DataFrame(columns=["timestamp", "value"])

    values = results[0]["values"]

    df = pd.DataFrame(values, columns=["timestamp", "value"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
    df["value"] = df["value"].astype(float)

    return df

def detect_anomalies(df):
    """Entraine un Isolation Forest et detecte les anomalies dans les donnees."""
    if len(df) == 0:
        return df

    model = IsolationForest(contamination=0.1, random_state=42)
    X = df[["value"]]
    df["anomaly"] = model.fit_predict(X)
    # anomaly == -1 -> anomalie detectee / anomaly == 1 -> normal

    return df

if __name__ == "__main__":
    df = get_metric_data("node_load1", duration_minutes=10)
    df = detect_anomalies(df)

    print(df)
    if len(df) > 0:
        print(f"\nNombre d'anomalies detectees : {(df['anomaly'] == -1).sum()} / {len(df)}")

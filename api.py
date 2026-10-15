from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from collect_metrics import get_metric_data, detect_anomalies
from smart_detection import (
    check_cpu_anomalies_ai, check_ram_anomalies_ai,
    check_system_cpu_ai, check_system_ram_ai, check_disk_space_ai,
    check_stopped_containers, check_crash_loop, check_memory_leak
)
from auth import create_user, authenticate_user, create_access_token, decode_access_token
from history import save_all_anomalies, get_anomalies_history, get_anomaly_stats
from auto_healing import auto_heal, get_healing_actions, get_healing_stats, auto_healing_state

import docker
import threading
import time

app = FastAPI(title="Supervision IA - API")

# Autorise React (sur un autre port) a appeler cette API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

docker_client = docker.from_env()

# --- Authentification ---

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expire"
        )
    return payload

@app.post("/register")
def register(data: RegisterRequest):
    success = create_user(data.username, data.email, data.password)
    if not success:
        raise HTTPException(status_code=400, detail="Nom d'utilisateur ou email deja utilise")
    return {"message": "Compte cree avec succes"}

@app.post("/login")
def login(data: LoginRequest):
    user = authenticate_user(data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"]
    }

@app.get("/me")
def read_current_user(current_user: dict = Depends(get_current_user)):
    """Route protegee : renvoie les infos de l'utilisateur connecte."""
    return current_user

# --- Supervision / Detection d'anomalies ---

latest_status = {"results": [], "last_update": None}

def run_all_checks():
    """Execute toutes les verifications et retourne une liste unique de resultats."""
    results = []
    results += check_cpu_anomalies_ai(docker_client)
    results += check_ram_anomalies_ai(docker_client)
    results += check_system_cpu_ai()
    results += check_system_ram_ai()
    results += check_disk_space_ai()
    results += check_stopped_containers(docker_client)
    results += check_crash_loop(docker_client)
    results += check_memory_leak()
    return results

def background_loop():
    """Tourne en continu, recalcule les anomalies toutes les 10 secondes."""
    while True:
        try:
            results = run_all_checks()
            latest_status["results"] = results
            latest_status["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
            save_all_anomalies(results)
            auto_heal(docker_client, results)
        except Exception as e:
            print("Erreur dans background_loop:", e)
        time.sleep(10)

@app.on_event("startup")
def start_background_task():
    thread = threading.Thread(target=background_loop, daemon=True)
    thread.start()

@app.get("/live-status")
def live_status():
    """Retourne le dernier etat calcule (JSON) - utilise par le dashboard React."""
    return latest_status

@app.get("/anomalies-history")
def anomalies_history(limit: int = 100, container: str = None):
    """Retourne l'historique des anomalies enregistrees en base."""
    return get_anomalies_history(limit=limit, container=container)

@app.get("/anomaly-stats")
def anomaly_stats(hours: int = 24):
    """Retourne des statistiques agregees sur les X dernieres heures."""
    return get_anomaly_stats(hours=hours)

@app.get("/healing-actions")
def healing_actions(limit: int = 100):
    """Retourne l'historique des actions d'auto-remediation effectuees."""
    return get_healing_actions(limit=limit)

@app.get("/healing-stats")
def healing_stats():
    """Retourne des statistiques sur l'auto-remediation (nb actions, etat activation)."""
    return get_healing_stats()

class HealingToggle(BaseModel):
    enabled: bool

@app.post("/healing-toggle")
def healing_toggle(data: HealingToggle):
    """Active ou desactive l'auto-remediation."""
    auto_healing_state["enabled"] = data.enabled
    return {"auto_healing_enabled": auto_healing_state["enabled"]}

@app.get("/metrics/{metric_name}")
def get_metrics(metric_name: str, duration_minutes: int = 10):
    df = get_metric_data(metric_name, duration_minutes=duration_minutes)
    return df.to_dict(orient="records")

@app.get("/anomalies/{metric_name}")
def get_anomalies(metric_name: str, duration_minutes: int = 10):
    df = get_metric_data(metric_name, duration_minutes=duration_minutes)
    df = detect_anomalies(df)
    return df.to_dict(orient="records")

@app.get("/")
def root():
    return {"message": "Supervision IA API - operationnelle. Voir /docs pour la documentation."}
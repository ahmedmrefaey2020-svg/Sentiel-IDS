import os
from time import time, sleep
from fastapi import FastAPI, Header, Request, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, StreamingResponse
import io
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from backend.database import SessionLocal, get_latest_network_stats, get_settings_db
from backend.models import BlockedIP, NetworkFlow, SystemSetting
from backend.ML.machine_learning import analyze_payload_ML, run_network_check_ML
from backend.DL.deep_learning import run_network_check_DL, analyze_payload_DL
from pydantic import BaseModel
import threading
import asyncio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")
load_dotenv()

stop_sniffing = threading.Event()
last_external_data_time = 0.0

class Settings(BaseModel):
    orgName: str
    activeModel: str
    confidence: int
    token: str
    monitoringMode: str = "scapy"

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

@app.on_event("startup")
def startup_event():
    threading.Thread(target=network_monitor, daemon=True).start()

def compute_dynamic_xai(data, active_model):
    is_anomaly = data.get("is_anomaly", False)
    risk_score = data.get("risk_score", 10)
    flows = data.get("network_flows", [])
    
    tcp_count = sum(1 for f in flows if f.get("proto") == "TCP")
    total_flows = len(flows) or 1
    
    syn_val = round((tcp_count / total_flows) * (25.5 if is_anomaly else 2.5), 1)
    byte_val = round((risk_score * 0.2), 1)
    ack_val = round(-10.5 if is_anomaly else -0.5, 1)

    return {
        "title": "DDoS Attack Expected" if is_anomaly else "Normal Traffic Patterns",
        "confidence": min(99, max(50, risk_score + 5)) if is_anomaly else min(30, max(5, risk_score)),
        "target_ip": flows[0]["src"] if flows else "192.168.1.105",
        "model_name": "LSTM (v2.4)" if active_model == "lstm" else "Baseline ML",
        "features": [
            {"name": "SYN Rate", "value": syn_val},
            {"name": "Byte Count", "value": byte_val},
            {"name": "ACK Rate", "value": ack_val}
        ]
    }

def analyze_external_payload(data):
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        active_model = db_settings.active_model
    finally:
        db.close()
        
    prediction = 0
    if active_model == "lstm":
        prediction = analyze_payload_DL(data)
    else:
        prediction = analyze_payload_ML(data)
        
    return {
        "is_attack": bool(prediction == 1),
        "message": "Attack Detected!" if prediction == 1 else "Traffic Normal"
    }

@app.post("/update-settings")
@limiter.limit("20/minute")
async def update_settings(request: Request, settings: Settings):
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        db_settings.org_name = settings.orgName
        db_settings.active_model = settings.activeModel
        db_settings.confidence_threshold = settings.confidence
        db_settings.api_key = settings.token
        db_settings.monitoring_mode = settings.monitoringMode
        db.commit()
    finally:
        db.close()
    return {"status": "success"}

def network_monitor():
    global last_external_data_time
    current_mode = None
    
    while not stop_sniffing.is_set():
        try:
            db = SessionLocal()
            try:
                db_settings = get_settings_db(db)
                mode = db_settings.monitoring_mode
                model = db_settings.active_model
            except Exception:
                mode = "scapy"
                model = "lstm"
            finally:
                db.close()
                
            if mode == "api_agent":
                current_mode = "api_agent"
                if time() - last_external_data_time > 15.0:
                    if model == "lstm":
                        run_network_check_DL()
                    else:
                        run_network_check_ML()
                sleep(1)
            else:
                if current_mode != "scapy":
                    current_mode = "scapy"

                if model == "lstm":
                    run_network_check_DL()
                else:
                    run_network_check_ML()
                sleep(1)
        except Exception:
            sleep(1)

@app.post("/api/external-data-ingest")
@limiter.limit("120/minute")
async def ingest_external_data(request: Request, data: dict, token: str = Header(...)):
    global last_external_data_time
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        user_api_token = db_settings.api_key
        mode = db_settings.monitoring_mode
    finally:
        db.close()
        
    if mode != "api_agent" or token != user_api_token:
        raise HTTPException(status_code=403, detail="Invalid Token or Mode")
        
    last_external_data_time = time()
    result = analyze_external_payload(data)
    return {"status": "analyzed", "result": result}

@app.post("/api/block-ip")
async def block_ip_endpoint(data: dict):
    ip_to_block = data.get("ip")
    db = SessionLocal()
    try:
        existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_to_block).first()
        if not existing:
            new_block = BlockedIP(ip_address=ip_to_block, protocol="TCP", port=0, src_bytes=0)
            db.add(new_block)
            db.commit()
            return {"status": "success", "message": f"IP {ip_to_block} has been blocked."}
        return {"status": "info", "message": "IP already blocked."}
    finally:
        db.close()

@app.get("/download-agent")
async def download_agent(token: str, request: Request):
    base_url = str(request.base_url).rstrip('/')
    with open("backend/agent_template.py", "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace("REPLACE_WITH_USER_TOKEN", token)
    content = content.replace("REPLACE_WITH_YOUR_SITE_URL", base_url)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/x-python",
        headers={"Content-Disposition": "attachment; filename=sentinel_agent.py"}
    )
    
@app.middleware("http")
async def check_blocked_ips(request: Request, call_next):
    if request.url.path.startswith("/static"):
        return await call_next(request)
        
    client_ip = request.client.host if request.client else None
    if client_ip:
        db = SessionLocal()
        try:
            is_blocked = db.query(BlockedIP).filter(BlockedIP.ip_address == client_ip).first()
        finally:
            db.close()
        
        if is_blocked:
            return JSONResponse(
                status_code=403, 
                content={"detail": "Your IP has been blocked."}
            )
    return await call_next(request)

@app.get("/api/dashboard-data")
async def get_dashboard_data():
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        active_model = db_settings.active_model
        mode = db_settings.monitoring_mode
        
        is_fallback_active = False
        if mode == "api_agent" and (time() - last_external_data_time > 15.0):
            is_fallback_active = True
            
        data = get_latest_network_stats(model_type=active_model)
        data["monitoring_mode"] = mode
        data["is_fallback_active"] = is_fallback_active
        data["user_api_token"] = db_settings.api_key
        data["active_model"] = active_model
        data["xai_explanation"] = compute_dynamic_xai(data, active_model)
        return data
    finally:
        db.close()

@app.websocket("/ws/live-traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await get_dashboard_data()
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

@app.get("/api/dataset-explorer-data")
async def get_explorer_data():
    db = SessionLocal()
    try:
        flows = db.query(NetworkFlow).all()
        return flows
    finally:
        db.close()

@app.get("/api/get-settings")
async def get_settings():
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        return {
            "orgName": db_settings.org_name,
            "activeModel": db_settings.active_model,
            "confidence": db_settings.confidence_threshold,
            "token": db_settings.api_key,
            "monitoringMode": db_settings.monitoring_mode
        }
    finally:
        db.close()

@app.get("/", include_in_schema=False, name="home")
async def home(request: Request):
    return templates.TemplateResponse(
        name="index.html",
        request=request
    )

@app.get("/Dashboard", include_in_schema=False, name="dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/dashboard.html",
        request=request
    )

@app.get("/Dataset-Explorer", include_in_schema=False, name="dataset_explorer")
async def dataset_explorer(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/dataset-explorer.html",
        request=request
    )

@app.get("/Network-Traffic", include_in_schema=False, name="network_traffic")
async def network_traffic(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/network-traffic.html",
        request=request
    )

@app.get("/Prediction-Timeline", include_in_schema=False, name="prediction_timeline")
async def prediction_timeline(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/prediction-timeline.html",
        request=request
    )

@app.get("/Research-Metrics", include_in_schema=False, name="research_metrics")
async def research_metrics(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/research-metrics.html",
        request=request
    )

@app.get("/Settings", include_in_schema=False, name="settings")
async def settings(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/settings.html",
        request=request
    )

@app.get("/Threat-Intelligence", include_in_schema=False, name="threat_intelligence")
async def threat_intelligence(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/threat-intelligence.html",
        request=request
    )

@app.get("/XAI-Dashboard", include_in_schema=False, name="xai_dashboard")
async def xai_dashboard(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/Dashboard/xai-dashboard.html",
        request=request
    )

@app.get("/Architecture", include_in_schema=False, name="architecture")
async def architecture(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/research/architecture.html",
        request=request
    )

@app.get("/Contributions", include_in_schema=False, name="contributions")
async def contributions(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/research/contributions.html",
        request=request
    )

@app.get("/Experiment-Results", include_in_schema=False, name="experiment_results")
async def experiment_results(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/research/experimental-results.html",
        request=request
    )

@app.get("/Methodology", include_in_schema=False, name="methodology")
async def methodology(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/research/methodology.html",
        request=request
    )

@app.get("/Research-Paper", include_in_schema=False, name="research_paper")
async def research_paper(request: Request):
    return templates.TemplateResponse(
        name="FrontEnd/research/research-paper.html",
        request=request
    )
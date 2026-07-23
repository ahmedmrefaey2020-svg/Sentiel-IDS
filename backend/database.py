from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.models import Base, SystemSetting

DATABASE_URL = "sqlite:///./ips_data.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_settings_db(db: Session):
    settings = db.query(SystemSetting).first()
    if not settings:
        settings = SystemSetting(
            org_name="My Network",
            admin_email="admin@network.local",
            timezone="UTC",
            push_notifications=True,
            email_alerts=True,
            auto_block=False,
            active_model="lstm",
            confidence_threshold=85,
            monitoring_mode="scapy",
            api_key=""
        )
        db.add(settings)
        try:
            db.commit()
            db.refresh(settings)
        except Exception:
            db.rollback()
            raise
    return settings

def get_latest_network_stats(model_type="lstm"):
    from backend.ML.machine_learning import stats as ml_stats
    from backend.DL.deep_learning import stats as dl_stats
    from backend.models import BlockedIP

    if model_type in {"ml", "rf"}:
        current_stats = ml_stats
    else:
        current_stats = dl_stats
    
    db = SessionLocal()
    try:
        recent_blocks = db.query(BlockedIP).order_by(BlockedIP.id.desc()).limit(5).all()
        blocked_list = [
            {"time": "Blocked", "src": b.ip_address, "port": b.port, "proto": b.protocol, "status": "anomaly"} 
            for b in recent_blocks
        ]
    finally:
        db.close()
    
    return {
        "active_connections": current_stats["connections"],
        "packet_rate": current_stats["packet_rate"],
        "risk_score": current_stats["score"],
        "risk_message": current_stats["message"],
        "is_anomaly": current_stats["is_anomaly"],
        "network_flows": current_stats.get("recent_flows", []), 
        "blocked_list": blocked_list
    }
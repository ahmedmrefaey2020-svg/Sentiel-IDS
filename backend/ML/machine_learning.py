import os
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv
from datetime import datetime
from backend.database import SessionLocal
from backend.models import BlockedIP, NetworkFlow
import time
from collections import deque
import threading
import joblib

load_dotenv()

# حدد مسار ملف الموديل المحلي للـ Machine Learning
MODEL_PATH = os.path.join(os.path.dirname(__file__), "RandomForest_model.pkl")  # عدل الاسم لو مختلف

_local_model = None
_model_lock = threading.Lock()

def _load_local_model():
    global _local_model
    if _local_model is None:
        try:
            if os.path.exists(MODEL_PATH):
                _local_model = joblib.load(MODEL_PATH)
                print(f"Loaded local ML model successfully from {MODEL_PATH}")
            else:
                print(f"Warning: Local model file not found at {MODEL_PATH}. Using fallback logic.")
        except Exception as e:
            print(f"Error loading local ML model: {e}")
            _local_model = None
    return _local_model

def local_fallback_predict(payload_data):
    src_bytes = payload_data.get('TotLen Fwd Pkts', 0)
    count = payload_data.get('Flow Pkts/s', 1)
    duration = payload_data.get('Flow Duration', 0.0)
    
    if src_bytes > 50000 or count > 100 or (duration > 0 and (src_bytes / max(duration, 0.001)) > 100000):
        return 1
    return 0

def analyze_payload_ML(payload_data):
    model = _load_local_model()
    
    if model is None:
        return local_fallback_predict(payload_data)

    try:
        # استخراج الـ 24 ميزة بالترتيب الصحيح تماماً مثل التدريب
        features_list = [
            payload_data.get('Flow Duration', 0.0),
            payload_data.get('Flow IAT Mean', 0.0),
            payload_data.get('Flow IAT Max', 0.0),
            payload_data.get('Flow IAT Min', 0.0),
            payload_data.get('TotLen Fwd Pkts', 0.0),
            payload_data.get('TotLen Bwd Pkts', 0.0),
            payload_data.get('Fwd Pkt Len Max', 0.0),
            payload_data.get('Fwd Pkt Len Mean', 0.0),
            payload_data.get('Bwd Pkt Len Max', 0.0),
            payload_data.get('Bwd Pkt Len Mean', 0.0),
            payload_data.get('Pkt Size Avg', 0.0),
            payload_data.get('FIN Flag Cnt', 0.0),
            payload_data.get('SYN Flag Cnt', 0.0),
            payload_data.get('RST Flag Cnt', 0.0),
            payload_data.get('PSH Flag Cnt', 0.0),
            payload_data.get('ACK Flag Cnt', 0.0),
            payload_data.get('URG Flag Cnt', 0.0),
            payload_data.get('Init Fwd Win Byts', 0.0),
            payload_data.get('Init Bwd Win Byts', 0.0),
            payload_data.get('Flow Byts/s', 0.0),
            payload_data.get('Flow Pkts/s', 0.0),
            payload_data.get('Fwd Pkt Len Std', 0.0),
            payload_data.get('Pkt Len Var', 0.0),
            payload_data.get('Fwd Header Len', 0.0)
        ]

        # تمرير الـ 24 ميزة للموديل بالشكل المتوقع (2D Array)
        features = [features_list]
        
        with _model_lock:
            prediction = model.predict(features)[0]
            
        return int(prediction)
    except Exception as e:
        print(f"Error during local model prediction: {e}. Falling back.")
        return local_fallback_predict(payload_data)

def _get_monitoring_config_from_db():
    from backend.database import get_settings_db

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        mode = getattr(db_settings, "monitoring_mode", "scapy")
        model = getattr(db_settings, "active_model", "rf")
        return mode, model
    finally:
        db.close()

stats = {
    "connections": 0,
    "packet_rate": 0,
    "score": 10,
    "message": "System is stable.",
    "is_anomaly": False,
    "recent_flows": []
}

packet_queue = deque(maxlen=200)
queue_lock = threading.Lock()

def block_ip(ip_address, protocol, port, src_bytes):
    db = SessionLocal()
    try:
        existing_block = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
        if not existing_block:
            new_block = BlockedIP(
                ip_address=ip_address,
                protocol=protocol,
                port=port,
                src_bytes=src_bytes
            )
            db.add(new_block)
            db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error saving to database: {e}")
    finally:
        db.close()

def process_and_predict_packet(packet):
    global stats
    if packet.haslayer(IP):
        with queue_lock:
            packet_queue.append(packet)
            
        # زيادة العداد فوراً وبكل سرعة لتصل للآلاف كما هو مطلوب
        stats["connections"] += 1
        
        src_bytes = len(packet)
        protocol = "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else "other")
        port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        
        payload_data = {
            'Flow Duration': 0.0,
            'Flow IAT Mean': 0.0,
            'Flow IAT Max': 0.0,
            'Flow IAT Min': 0.0,
            'TotLen Fwd Pkts': src_bytes,
            'TotLen Bwd Pkts': 0.0,
            'Fwd Pkt Len Max': src_bytes,
            'Fwd Pkt Len Mean': src_bytes,
            'Bwd Pkt Len Max': 0.0,
            'Bwd Pkt Len Mean': 0.0,
            'Pkt Size Avg': src_bytes,
            'FIN Flag Cnt': 1.0 if packet.haslayer(TCP) and 'F' in str(packet[TCP].flags) else 0.0,
            'SYN Flag Cnt': 1.0 if packet.haslayer(TCP) and 'S' in str(packet[TCP].flags) else 0.0,
            'RST Flag Cnt': 1.0 if packet.haslayer(TCP) and 'R' in str(packet[TCP].flags) else 0.0,
            'PSH Flag Cnt': 1.0 if packet.haslayer(TCP) and 'P' in str(packet[TCP].flags) else 0.0,
            'ACK Flag Cnt': 1.0 if packet.haslayer(TCP) and 'A' in str(packet[TCP].flags) else 0.0,
            'URG Flag Cnt': 1.0 if packet.haslayer(TCP) and 'U' in str(packet[TCP].flags) else 0.0,
            'Init Fwd Win Byts': packet[TCP].window if packet.haslayer(TCP) else 0.0,
            'Init Bwd Win Byts': 0.0,
            'Flow Byts/s': float(src_bytes),
            'Flow Pkts/s': 1.0,
            'Fwd Pkt Len Std': 0.0,
            'Pkt Len Var': 0.0,
            'Fwd Header Len': len(packet[TCP]) if packet.haslayer(TCP) else 0.0
        }
        
        prediction = 0
        try:
            prediction = analyze_payload_ML(payload_data)
            
            if prediction == 1:
                stats["is_anomaly"] = True
                stats["score"] = 92
                stats["message"] = "Machine Learning detected a threat (Local)!"
                block_ip(packet[IP].src, protocol, port, src_bytes)
            else:
                stats["is_anomaly"] = False
                stats["score"] = 5
                stats["message"] = "Traffic is clean (Local ML Analysis)."
                
        except Exception as e:
            print("Error during ML packet analysis loop:", e)

        time_str = datetime.now().strftime("%H:%M:%S")
        
        if len(stats["recent_flows"]) >= 50:
            stats["recent_flows"].pop(0)
            
        stats["recent_flows"].append({
            "time": time_str, 
            "src": packet[IP].src, 
            "port": port, 
            "proto": protocol, 
            "status": "anomaly" if prediction == 1 else "normal"
        })

        # الحفظ الذكي بقاعدة البيانات لمنع الـ Lag ولضمان استقرار السرعة العالية
        if prediction == 1 or stats["connections"] % 10 == 0:
            db = SessionLocal()
            try:
                dest_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
                new_flow = NetworkFlow(
                    time=time_str,
                    src=packet[IP].src,
                    dest=dest_ip,
                    proto=protocol.upper(),
                    duration="0.0",
                    packets=1,
                    isAttack=(prediction == 1),
                    label="Anomaly" if prediction == 1 else "Normal"
                )
                db.add(new_flow)
                db.commit()
            except Exception as db_err:
                db.rollback()
            finally:
                db.close()

def run_network_check_ML():
    global stats
    stats = {
        "connections": 0, 
        "packet_rate": 0, 
        "score": 5, 
        "message": "System is stable.", 
        "is_anomaly": False,
        "recent_flows": []
    }
    def stop_condition(pkt):
        mode, model = _get_monitoring_config_from_db()
        return mode != "scapy" or model not in {"rf", "ml"}
    
    try:
        sniff(prn=process_and_predict_packet, store=False, timeout=2, stop_filter=stop_condition)
    except Exception as e:
        print(f"ML Scapy error: {e}")
        stats["message"] = "ML Analysis Error (Scapy)"
    return stats
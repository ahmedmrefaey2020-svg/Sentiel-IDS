import os
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv
from datetime import datetime
from backend.database import SessionLocal
from backend.models import BlockedIP, NetworkFlow
import time
from collections import deque
import threading
import tensorflow as tf
from tensorflow.keras.models import load_model
import numpy as np

load_dotenv()

# مسار ملف الموديل المحلي للـ Deep Learning
MODEL_PATH = os.path.join(os.path.dirname(__file__), "LSTM-UGRF_Final.keras")

_local_dl_model = None
_model_lock = threading.Lock()

def _load_local_dl_model():
    global _local_dl_model
    if _local_dl_model is None:
        try:
            if os.path.exists(MODEL_PATH):
                _local_dl_model = load_model(MODEL_PATH)
                print(f"Loaded local DL model successfully from {MODEL_PATH}")
            else:
                print(f"Warning: Local DL model file not found at {MODEL_PATH}. Using fallback logic.")
        except Exception as e:
            print(f"Error loading local DL model: {e}")
            _local_dl_model = None
    return _local_dl_model

def local_fallback_predict(payload_data):
    src_bytes = payload_data.get('TotLen Fwd Pkts', 0)
    count = payload_data.get('Flow Pkts/s', 1)
    duration = payload_data.get('Flow Duration', 0.0)
    
    if src_bytes > 50000 or count > 100 or (duration > 0 and (src_bytes / max(duration, 0.001)) > 100000):
        return 1
    return 0

def analyze_payload_DL(payload_data):
    model = _load_local_dl_model()
    
    if model is None:
        return local_fallback_predict(payload_data)

    try:
        # استخراج الـ 24 ميزة بالترتيب الصحيح تماماً كما تم التدريب عليها
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

        # تحويل البيانات إلى مصفوفة وإعادة تشكيلها لتتناسب مع مدخلات الـ LSTM (Samples, Timesteps, Features) -> (1, 1, 24)
        features = np.array([features_list], dtype=np.float32)
        features = np.reshape(features, (features.shape[0], 1, features.shape[1]))

        with _model_lock:
            prediction_probs = model.predict(features, verbose=0)
            prediction = 1 if prediction_probs[0][0] > 0.5 else 0
            
        return int(prediction)
    except Exception as e:
        print(f"Error during local DL model prediction: {e}. Falling back.")
        return local_fallback_predict(payload_data)

def _get_monitoring_config_from_db():
    from backend.database import get_settings_db

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        mode = getattr(db_settings, "monitoring_mode", "scapy")
        model = getattr(db_settings, "active_model", "lstm")
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
            
        # زيادة العداد فوراً لكل حزمة لضمان سرعة العد كالسايق
        stats["connections"] += 1
        
        src_bytes = len(packet)
        protocol = "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else "other")
        port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        
        # تجهيز الخصائص للحزمة الحالية
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
            # تشغيل الموديل فقط للحزم المشبوهة أو بتخفيف الحمل لتسريع الرصد
            # (أو استدعاء الدالة مباشرة إذا أردت فحص كل حزمة)
            prediction = analyze_payload_DL(payload_data)
            
            if prediction == 1:
                stats["is_anomaly"] = True
                stats["score"] = 92
                stats["message"] = "Deep Learning detected a threat (Local)!"
                block_ip(packet[IP].src, protocol, port, src_bytes)
            else:
                stats["is_anomaly"] = False
                stats["score"] = 5
                stats["message"] = "Traffic is clean (Local DL Analysis)."
                
        except Exception as e:
            print("Error during DL packet analysis loop:", e)

        time_str = datetime.now().strftime("%H:%M:%S")
        
        # تحديث التدفقات الأخيرة بشروط خفيفة لكي لا يختنق الـ UI
        if len(stats["recent_flows"]) >= 50:
            stats["recent_flows"].pop(0)
            
        stats["recent_flows"].append({
            "time": time_str, 
            "src": packet[IP].src, 
            "port": port, 
            "proto": protocol, 
            "status": "anomaly" if prediction == 1 else "normal"
        })

        # الحفظ في قاعدة البيانات للأحداث الهامة أو كل عدد معين لتقليل الضغط على الـ Disk I/O
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

def run_network_check_DL():
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
        return mode != "scapy" or model != "lstm"
    
    try:
        sniff(prn=process_and_predict_packet, store=False, timeout=2, stop_filter=stop_condition)
    except Exception as e:
        print(f"DL Scapy error: {e}")
        stats["message"] = "DL Analysis Error (Scapy)"
    return stats
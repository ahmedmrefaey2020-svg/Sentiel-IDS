from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    protocol = Column(String)
    port = Column(Integer)
    src_bytes = Column(Integer)
    
class NetworkFlow(Base):
    __tablename__ = "network_flows"
    id = Column(Integer, primary_key=True, index=True)
    time = Column(String)
    src = Column(String)
    dest = Column(String)
    proto = Column(String)
    duration = Column(String)
    packets = Column(Integer)
    isAttack = Column(Boolean)
    label = Column(String)

class SystemSetting(Base):
    __tablename__ = "system_settings"
    id = Column(Integer, primary_key=True, index=True)
    org_name = Column(String, default="My Network")
    admin_email = Column(String, default="admin@network.local")
    timezone = Column(String, default="UTC")
    push_notifications = Column(Boolean, default=True)
    email_alerts = Column(Boolean, default=True)
    auto_block = Column(Boolean, default=False)
    active_model = Column(String, default="lstm")
    confidence_threshold = Column(Integer, default=85)
    monitoring_mode = Column(String, default="scapy")
    api_key = Column(String, default="")
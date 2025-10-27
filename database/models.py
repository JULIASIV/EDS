# database/models.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy import Index, text
import datetime

Base = declarative_base()

class Endpoint(Base):
    __tablename__ = "endpoints"
    
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=True, index=True)
    ip_address = Column(String(45))
    mac_address = Column(String(17))
    os_version = Column(String(100))
    agent_version = Column(String(50))
    last_seen = Column(DateTime, default=func.now())
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())

class ProcessEvent(Base):
    __tablename__ = "process_events"
    
    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    timestamp = Column(DateTime, default=func.now())
    process_name = Column(String(255))
    process_id = Column(Integer)
    parent_process_id = Column(Integer)
    parent_process_name = Column(String(255))
    command_line = Column(Text)
    integrity_level = Column(String(50))
    user_name = Column(String(255))
    is_suspicious = Column(Boolean, default=False)
    suspicion_reason = Column(Text)
    sha256_hash = Column(String(64))  # Process image hash

class NetworkEvent(Base):
    __tablename__ = "network_events"
    
    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    timestamp = Column(DateTime, default=func.now())
    process_name = Column(String(255))
    process_id = Column(Integer)
    local_address = Column(String(45))
    local_port = Column(Integer)
    remote_address = Column(String(45))
    remote_port = Column(Integer)
    protocol = Column(String(10))
    connection_state = Column(String(20))
    is_suspicious = Column(Boolean, default=False)

class FileEvent(Base):
    __tablename__ = "file_events"
    
    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    timestamp = Column(DateTime, default=func.now())
    process_name = Column(String(255))
    process_id = Column(Integer)
    file_path = Column(Text)
    operation = Column(String(50))  # CREATE, MODIFY, DELETE
    file_hash = Column(String(64))
    is_suspicious = Column(Boolean, default=False)

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    description = Column(Text)
    rule_type = Column(String(50))  # PROCESS, NETWORK, FILE
    condition = Column(JSON)  # JSON structure for rule conditions
    severity = Column(String(20))  # LOW, MEDIUM, HIGH, CRITICAL
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())

    # Add these after table definitions
Index('idx_process_events_endpoint_timestamp', ProcessEvent.endpoint_id, ProcessEvent.timestamp)
Index('idx_process_events_suspicious', ProcessEvent.is_suspicious, ProcessEvent.timestamp)
Index('idx_network_events_remote_ip', NetworkEvent.remote_address, NetworkEvent.timestamp)
Index('idx_events_timestamp', ProcessEvent.timestamp)
Index('idx_endpoints_last_seen', Endpoint.last_seen)
# server/routes/agents.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import Endpoint
from server.auth import verify_token, create_access_token
from config.settings import settings
from pydantic import BaseModel
from typing import Optional
import datetime

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str
    mac_address: str
    os_version: str
    agent_version: str
    registration_token: str

class Heartbeat(BaseModel):
    hostname: str

@router.post("/register")
async def register_agent(
    registration: AgentRegistration,
    db: Session = Depends(get_db)
):
    # Verify registration token
    if registration.registration_token != settings.AGENT_REGISTRATION_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid registration token")
    
    # Check if agent already exists
    existing_agent = db.query(Endpoint).filter(
        Endpoint.hostname == registration.hostname
    ).first()
    
    if existing_agent:
        # Update existing agent
        existing_agent.ip_address = registration.ip_address
        existing_agent.mac_address = registration.mac_address
        existing_agent.os_version = registration.os_version
        existing_agent.agent_version = registration.agent_version
        existing_agent.last_seen = datetime.datetime.utcnow()
        existing_agent.is_active = True
    else:
        # Create new agent
        agent = Endpoint(
            hostname=registration.hostname,
            ip_address=registration.ip_address,
            mac_address=registration.mac_address,
            os_version=registration.os_version,
            agent_version=registration.agent_version,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(agent)
    
    db.commit()
    
    # Generate access token for the agent
    access_token = create_access_token(
        data={"sub": registration.hostname},
        expires_delta=datetime.timedelta(days=365)  # Long-lived token for agents
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "agent_id": existing_agent.id if existing_agent else agent.id,
        "checkin_interval": settings.AGENT_CHECKIN_INTERVAL
    }

@router.post("/heartbeat")
async def agent_heartbeat(
    heartbeat: Heartbeat,
    db: Session = Depends(get_db),
    token: dict = Depends(verify_token)
):
    agent = db.query(Endpoint).filter(
        Endpoint.hostname == heartbeat.hostname
    ).first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.last_seen = datetime.datetime.utcnow()
    agent.is_active = True
    db.commit()
    
    return {"status": "ok", "timestamp": agent.last_seen.isoformat()}
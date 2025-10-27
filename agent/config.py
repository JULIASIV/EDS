# agent/config.py
import os
import json
from dataclasses import dataclass
from typing import Optional

@dataclass
class AgentConfig:
    server_url: str = "http://localhost:8000"
    agent_id: Optional[str] = None
    hostname: str = ""
    registration_token: str = "initial-registration-token"
    checkin_interval: int = 30
    heartbeat_interval: int = 60
    
    @classmethod
    def load_from_file(cls, config_path: str = "agent_config.json"):
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                data = json.load(f)
                return cls(**data)
        return cls()
    
    def save_to_file(self, config_path: str = "agent_config.json"):
        with open(config_path, 'w') as f:
            json.dump(self.__dict__, f, indent=2)

class APIClient:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.base_url = config.server_url
        self.session = requests.Session()
        if config.agent_id:
            self.session.headers.update({
                "Authorization": f"Bearer {config.agent_id}"
            })
    
    def register_agent(self):
        registration_data = {
            "hostname": self.config.hostname,
            "ip_address": self.get_ip_address(),
            "mac_address": self.get_mac_address(),
            "os_version": self.get_os_version(),
            "agent_version": "1.0.0",
            "registration_token": self.config.registration_token
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/agents/register",
            json=registration_data
        )
        
        if response.status_code == 200:
            data = response.json()
            self.config.agent_id = data["access_token"]
            self.config.checkin_interval = data["checkin_interval"]
            self.config.save_to_file()
            self.session.headers.update({
                "Authorization": f"Bearer {data['access_token']}"
            })
            return True
        return False
    
    def send_heartbeat(self):
        response = self.session.post(
            f"{self.base_url}/api/v1/agents/heartbeat",
            json={"hostname": self.config.hostname}
        )
        return response.status_code == 200
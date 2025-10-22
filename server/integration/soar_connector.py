# server/integration/soar_connector.py
import requests
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

class SOARConnector:
    def __init__(self, soar_config: Dict):
        self.soar_config = soar_config
        self.base_url = soar_config.get('base_url')
        self.api_key = soar_config.get('api_key')
        self.verify_ssl = soar_config.get('verify_ssl', True)
        
    async def create_incident(self, alert_data: Dict) -> Optional[str]:
        """Create incident in SOAR platform"""
        try:
            incident_data = self.format_incident_data(alert_data)
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.base_url}/incidents",
                json=incident_data,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 201:
                incident_id = response.json().get('id')
                logging.info(f"Created SOAR incident: {incident_id}")
                return incident_id
            else:
                logging.error(f"SOAR incident creation failed: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"SOAR integration error: {e}")
            return None
    
    def format_incident_data(self, alert_data: Dict) -> Dict[str, Any]:
        """Format alert data for SOAR incident"""
        return {
            'name': f"EDR Alert: {alert_data.get('event_type', 'Unknown')}",
            'description': alert_data.get('data', {}).get('description', ''),
            'severity': self.map_severity(alert_data.get('severity', 'MEDIUM')),
            'status': 'New',
            'created_date': datetime.utcnow().isoformat(),
            'alert_data': alert_data,
            'endpoint_id': alert_data.get('agent_id'),
            'process_name': alert_data.get('data', {}).get('process_name'),
            'recommendation': alert_data.get('data', {}).get('recommendation', '')
        }
    
    def map_severity(self, edr_severity: str) -> int:
        """Map EDR severity to SOAR severity scale"""
        severity_map = {
            'LOW': 1,
            'MEDIUM': 2, 
            'HIGH': 3,
            'CRITICAL': 4
        }
        return severity_map.get(edr_severity, 2)
    
    async def add_evidence_to_incident(self, incident_id: str, evidence_data: Dict):
        """Add evidence to existing SOAR incident"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.base_url}/incidents/{incident_id}/evidence",
                json=evidence_data,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                logging.info(f"Added evidence to SOAR incident: {incident_id}")
            else:
                logging.error(f"Failed to add evidence to SOAR incident: {response.status_code}")
                
        except Exception as e:
            logging.error(f"SOAR evidence addition error: {e}")
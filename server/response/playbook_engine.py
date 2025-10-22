# server/response/playbook_engine.py
from typing import Dict, List, Any, Callable
from enum import Enum
import logging
from datetime import datetime

class PlaybookAction(Enum):
    ISOLATE_ENDPOINT = "isolate_endpoint"
    KILL_PROCESS = "kill_process"
    COLLECT_FORENSICS = "collect_forensics"
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    NOTIFY_SOC = "notify_soc"
    CREATE_INCIDENT = "create_incident"

class Playbook:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.actions: List[Dict] = []
        self.conditions: List[Callable] = []
    
    def add_condition(self, condition: Callable):
        """Add condition to playbook"""
        self.conditions.append(condition)
    
    def add_action(self, action: PlaybookAction, parameters: Dict = None):
        """Add action to playbook"""
        self.actions.append({
            'action': action,
            'parameters': parameters or {},
            'executed': False,
            'result': None
        })
    
    def should_execute(self, alert_data: Dict) -> bool:
        """Check if playbook should execute for given alert"""
        return all(condition(alert_data) for condition in self.conditions)

class PlaybookEngine:
    def __init__(self, db_session):
        self.db = db_session
        self.playbooks: List[Playbook] = []
        self.load_playbooks()
    
    def load_playbooks(self):
        """Load automated response playbooks"""
        
        # Playbook for critical malware detection
        malware_playbook = Playbook(
            name="Critical Malware Response",
            description="Automated response for critical malware detection"
        )
        
        malware_playbook.add_condition(
            lambda alert: alert.get('severity') == 'CRITICAL'
        )
        malware_playbook.add_condition(
            lambda alert: alert.get('event_type') == 'malware_detection'
        )
        
        malware_playbook.add_action(PlaybookAction.ISOLATE_ENDPOINT)
        malware_playbook.add_action(PlaybookAction.KILL_PROCESS)
        malware_playbook.add_action(PlaybookAction.COLLECT_FORENSICS)
        malware_playbook.add_action(PlaybookAction.QUARANTINE_FILE)
        malware_playbook.add_action(PlaybookAction.CREATE_INCIDENT)
        malware_playbook.add_action(PlaybookAction.NOTIFY_SOC)
        
        self.playbooks.append(malware_playbook)
        
        # Playbook for lateral movement detection
        lateral_movement_playbook = Playbook(
            name="Lateral Movement Response", 
            description="Automated response for lateral movement detection"
        )
        
        lateral_movement_playbook.add_condition(
            lambda alert: alert.get('event_type') == 'lateral_movement'
        )
        lateral_movement_playbook.add_condition(
            lambda alert: alert.get('confidence', 0) > 0.7
        )
        
        lateral_movement_playbook.add_action(PlaybookAction.BLOCK_IP)
        lateral_movement_playbook.add_action(PlaybookAction.ISOLATE_ENDPOINT)
        lateral_movement_playbook.add_action(PlaybookAction.CREATE_INCIDENT)
        
        self.playbooks.append(lateral_movement_playbook)
        
        # Playbook for ransomware detection
        ransomware_playbook = Playbook(
            name="Ransomware Response",
            description="Automated response for ransomware activity"
        )
        
        ransomware_playbook.add_condition(
            lambda alert: 'ransomware' in alert.get('data', {}).get('tags', [])
        )
        
        ransomware_playbook.add_action(PlaybookAction.ISOLATE_ENDPOINT)
        ransomware_playbook.add_action(PlaybookAction.KILL_PROCESS)
        ransomware_playbook.add_action(PlaybookAction.BLOCK_IP)
        ransomware_playbook.add_action(PlaybookAction.NOTIFY_SOC)
        
        self.playbooks.append(ransomware_playbook)
    
    async def execute_playbooks(self, alert_data: Dict) -> List[Dict]:
        """Execute all applicable playbooks for an alert"""
        executed_actions = []
        
        for playbook in self.playbooks:
            if playbook.should_execute(alert_data):
                logging.info(f"Executing playbook: {playbook.name}")
                
                for action in playbook.actions:
                    if not action['executed']:
                        try:
                            result = await self.execute_action(
                                action['action'], 
                                action['parameters'],
                                alert_data
                            )
                            
                            action['executed'] = True
                            action['result'] = result
                            
                            executed_actions.append({
                                'playbook': playbook.name,
                                'action': action['action'].value,
                                'result': result,
                                'timestamp': datetime.utcnow().isoformat()
                            })
                            
                        except Exception as e:
                            logging.error(f"Playbook action failed: {e}")
        
        return executed_actions
    
    async def execute_action(self, action: PlaybookAction, parameters: Dict, alert_data: Dict) -> Dict:
        """Execute a specific playbook action"""
        if action == PlaybookAction.ISOLATE_ENDPOINT:
            return await self.isolate_endpoint(alert_data.get('agent_id'))
        
        elif action == PlaybookAction.KILL_PROCESS:
            return await self.kill_process(
                alert_data.get('agent_id'),
                alert_data.get('data', {}).get('pid')
            )
        
        elif action == PlaybookAction.COLLECT_FORENSICS:
            return await self.collect_forensics(alert_data.get('agent_id'))
        
        elif action == PlaybookAction.BLOCK_IP:
            return await self.block_ip(
                alert_data.get('data', {}).get('remote_address')
            )
        
        elif action == PlaybookAction.QUARANTINE_FILE:
            return await self.quarantine_file(
                alert_data.get('data', {}).get('file_path')
            )
        
        elif action == PlaybookAction.NOTIFY_SOC:
            return await self.notify_soc(alert_data)
        
        elif action == PlaybookAction.CREATE_INCIDENT:
            return await self.create_incident(alert_data)
        
        return {'success': False, 'error': 'Unknown action'}
    
    async def isolate_endpoint(self, endpoint_id: str) -> Dict:
        """Isolate endpoint from network"""
        # Implementation would use agent communication
        return {'success': True, 'message': f'Endpoint {endpoint_id} isolated'}
    
    async def kill_process(self, endpoint_id: str, pid: int) -> Dict:
        """Kill malicious process"""
        # Implementation would use agent communication
        return {'success': True, 'message': f'Process {pid} killed'}
    
    async def collect_forensics(self, endpoint_id: str) -> Dict:
        """Collect forensic data from endpoint"""
        # Implementation would use agent communication
        return {'success': True, 'message': 'Forensics collected'}
    
    async def block_ip(self, ip_address: str) -> Dict:
        """Block IP address at network level"""
        # Implementation would integrate with firewall
        return {'success': True, 'message': f'IP {ip_address} blocked'}
    
    async def quarantine_file(self, file_path: str) -> Dict:
        """Quarantine malicious file"""
        # Implementation would use agent file operations
        return {'success': True, 'message': f'File {file_path} quarantined'}
    
    async def notify_soc(self, alert_data: Dict) -> Dict:
        """Notify SOC team"""
        # Implementation would use notification system
        return {'success': True, 'message': 'SOC notified'}
    
    async def create_incident(self, alert_data: Dict) -> Dict:
        """Create incident in ticketing system"""
        # Implementation would use SOAR integration
        return {'success': True, 'message': 'Incident created'}
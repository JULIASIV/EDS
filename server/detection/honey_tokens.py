# server/deception/honey_tokens.py
import os
import json
import secrets
import logging
from datetime import datetime
from typing import Dict, List, Set
import hashlib

class HoneyTokenManager:
    def __init__(self, db_session):
        self.db = db_session
        self.active_tokens: Dict[str, Dict] = {}
        self.canary_files: Set[str] = set()
        self.canary_registry: Set[str] = set()
        self.canary_services: Set[str] = set()
        
        self.setup_honey_tokens()
    
    def setup_honey_tokens(self):
        """Setup honey tokens and canary objects"""
        try:
            # Create honey tokens (fake credentials)
            self.create_honey_credentials()
            
            # Create canary files
            self.create_canary_files()
            
            # Create canary registry keys
            self.create_canary_registry()
            
            # Create canary services
            self.create_canary_services()
            
            logging.info("Honey tokens and canaries deployed successfully")
            
        except Exception as e:
            logging.error(f"Failed to setup honey tokens: {e}")
    
    def create_honey_credentials(self):
        """Create fake credentials that should never be used"""
        honey_users = [
            {
                'username': 'backup_admin',
                'password': 'SuperSecret123!',
                'domain': 'CORP',
                'description': 'Backup Administrator Account'
            },
            {
                'username': 'sql_service',
                'password': 'SqlS3rv1c3!@#',
                'domain': 'CORP', 
                'description': 'SQL Service Account'
            },
            {
                'username': 'domain_admin',
                'password': 'D0m41n@dm1n!!',
                'domain': 'CORP',
                'description': 'Domain Administrator'
            }
        ]
        
        for user in honey_users:
            token_id = hashlib.sha256(
                f"{user['username']}@{user['domain']}".encode()
            ).hexdigest()
            
            self.active_tokens[token_id] = {
                'type': 'credential',
                'username': user['username'],
                'domain': user['domain'],
                'password': user['password'],
                'description': user['description'],
                'created_at': datetime.utcnow(),
                'last_accessed': None,
                'access_count': 0
            }
    
    def create_canary_files(self):
        """Create canary files that should never be accessed"""
        canary_locations = [
            r"C:\ProgramData\Microsoft\Credentials\backup_keys.txt",
            r"C:\Windows\Temp\sql_config.conf",
            r"C:\Users\Public\Documents\network_diagram.pdf",
            r"C:\Program Files\Common Files\system\drivers\passwords.db"
        ]
        
        for file_path in canary_locations:
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Create file with enticing content
                with open(file_path, 'w') as f:
                    f.write(f"# Canary File - DO NOT ACCESS\n")
                    f.write(f"# Created: {datetime.utcnow()}\n")
                    f.write(f"# Token: {secrets.token_hex(32)}\n")
                    f.write(f"Database Password: SuperSecretDB123!\n")
                    f.write(f"SSH Key: ssh-rsa AAAAB3NzaC1yc2E...\n")
                    f.write(f"API Key: sk_live_{secrets.token_hex(24)}\n")
                
                self.canary_files.add(file_path)
                logging.info(f"Created canary file: {file_path}")
                
            except Exception as e:
                logging.debug(f"Could not create canary file {file_path}: {e}")
    
    def create_canary_registry(self):
        """Create canary registry keys"""
        canary_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemUpdate"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run\BackgroundSync")
        ]
        
        for hive, key_path in canary_keys:
            try:
                key = winreg.CreateKey(hive, key_path)
                winreg.SetValueEx(key, "CanaryToken", 0, winreg.REG_SZ, secrets.token_hex(32))
                winreg.CloseKey(key)
                
                self.canary_registry.add(f"{hive}_{key_path}")
                logging.info(f"Created canary registry key: {key_path}")
                
            except Exception as e:
                logging.debug(f"Could not create canary registry {key_path}: {e}")
    
    def create_canary_services(self):
        """Create canary services"""
        canary_services = [
            {
                'name': 'SystemMonitor',
                'display_name': 'Windows System Monitor',
                'description': 'Monitors system performance and security',
                'binary_path': r'C:\Windows\System32\svchost.exe -k netsvcs'
            },
            {
                'name': 'NetworkProtector', 
                'display_name': 'Network Protection Service',
                'description': 'Provides network security and monitoring',
                'binary_path': r'C:\Program Files\Windows Defender\MsMpEng.exe'
            }
        ]
        
        for service in canary_services:
            try:
                import win32service
                import win32con
                
                scm = win32service.OpenSCManager(
                    None, 
                    None, 
                    win32service.SC_MANAGER_CREATE_SERVICE
                )
                
                # Create service
                service_handle = win32service.CreateService(
                    scm,
                    service['name'],
                    service['display_name'],
                    win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_DISABLED,  # Start disabled
                    win32service.SERVICE_ERROR_IGNORE,
                    service['binary_path'],
                    None,
                    0,
                    None,
                    None,
                    None
                )
                
                win32service.CloseServiceHandle(service_handle)
                win32service.CloseServiceHandle(scm)
                
                self.canary_services.add(service['name'])
                logging.info(f"Created canary service: {service['name']}")
                
            except Exception as e:
                logging.debug(f"Could not create canary service {service['name']}: {e}")
    
    def check_canary_access(self, event: Dict) -> bool:
        """Check if event involves canary objects"""
        event_type = event.get('event_type')
        data = event.get('data', {})
        
        if event_type == 'file_operation':
            file_path = data.get('file_path', '')
            if file_path in self.canary_files:
                self.handle_canary_trigger('file', file_path, event)
                return True
        
        elif event_type == 'registry_operation':
            key_path = data.get('key_path', '')
            if key_path in self.canary_registry:
                self.handle_canary_trigger('registry', key_path, event)
                return True
        
        elif event_type == 'service_operation':
            service_name = data.get('service_name', '')
            if service_name in self.canary_services:
                self.handle_canary_trigger('service', service_name, event)
                return True
        
        return False
    
    def handle_canary_trigger(self, canary_type: str, canary_id: str, event: Dict):
        """Handle canary token trigger"""
        alert_data = {
            "event_type": "canary_trigger",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "CRITICAL",
            "data": {
                "canary_type": canary_type,
                "canary_id": canary_id,
                "trigger_event": event,
                "process_name": event.get('data', {}).get('process_name'),
                "user_name": event.get('data', {}).get('user_name'),
                "description": "HONEY TOKEN TRIGGERED - POSSIBLE INTRUSION",
                "recommendation": "IMMEDIATE INVESTIGATION REQUIRED - Possible attacker activity detected"
            }
        }
        
        # Send high-priority alert
        self.send_critical_alert(alert_data)
        
        logging.critical(
            f"HONEY TOKEN TRIGGERED: {canary_type} - {canary_id} "
            f"by process {event.get('data', {}).get('process_name')}"
        )
    
    def send_critical_alert(self, alert_data: Dict):
        """Send critical alert for canary triggers"""
        # This would integrate with alerting systems (Slack, PagerDuty, etc.)
        # For now, we'll log it as critical
        
        logging.critical(
            f"CRITICAL: Honey token triggered - {alert_data['data']['description']}"
        )
        
        # Additional actions:
        # - Isolate affected endpoint
        # - Block source IP
        # - Notify SOC team
        # - Start incident response
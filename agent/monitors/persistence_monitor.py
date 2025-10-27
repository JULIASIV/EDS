# agent/monitors/persistence_monitor.py
import winreg
import os
import logging
from datetime import datetime
from typing import Dict, List, Set
import threading
import time

class PersistenceMonitor:
    def __init__(self, event_callback, config):
        self.event_callback = event_callback
        self.config = config
        self.running = False
        self.thread = None
        
        # Known persistence locations
        self.persistence_locations = {
            'run_key': [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ],
            'scheduled_tasks': r"C:\Windows\System32\Tasks",
            'startup_folder': [
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            ],
            'services': r"SYSTEM\CurrentControlSet\Services",
            'wmi': None,  # WMI event subscriptions
            'winlogon': [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            ]
        }
        
        self.known_persistence = set()
        self.load_known_persistence()
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.thread.start()
        logging.info("Persistence Monitor started")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logging.info("Persistence Monitor stopped")
    
    def monitor_loop(self):
        """Monitor for persistence mechanism changes"""
        while self.running:
            try:
                self.check_registry_persistence()
                self.check_scheduled_tasks()
                self.check_startup_folder()
                self.check_services()
                self.check_wmi_persistence()
                
                time.sleep(self.config.persistence_check_interval)
                
            except Exception as e:
                logging.error(f"Persistence monitoring error: {e}")
                time.sleep(30)
    
    def check_registry_persistence(self):
        """Check registry run keys for new persistence"""
        for hive, key_path in self.persistence_locations['run_key']:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, i)
                            persistence_id = f"registry_{hive}_{key_path}_{value_name}"
                            
                            if persistence_id not in self.known_persistence:
                                self.handle_new_persistence(
                                    "registry_run_key",
                                    persistence_id,
                                    {
                                        'hive': hive,
                                        'key_path': key_path,
                                        'value_name': value_name,
                                        'value_data': value_data,
                                        'value_type': value_type
                                    }
                                )
                                self.known_persistence.add(persistence_id)
                            
                            i += 1
                        except WindowsError:
                            break
                            
            except Exception as e:
                logging.debug(f"Could not access registry key {key_path}: {e}")
    
    def check_scheduled_tasks(self):
        """Check for new scheduled tasks"""
        try:
            tasks_path = self.persistence_locations['scheduled_tasks']
            for root, dirs, files in os.walk(tasks_path):
                for file in files:
                    if file.endswith('.xml'):
                        task_path = os.path.join(root, file)
                        task_id = f"scheduled_task_{task_path}"
                        
                        if task_id not in self.known_persistence:
                            # Analyze task XML for suspicious properties
                            task_info = self.analyze_scheduled_task(task_path)
                            
                            if self.is_suspicious_task(task_info):
                                self.handle_new_persistence(
                                    "scheduled_task",
                                    task_id,
                                    task_info
                                )
                                self.known_persistence.add(task_id)
                                
        except Exception as e:
            logging.error(f"Scheduled task check failed: {e}")
    
    def check_services(self):
        """Check for new or suspicious services"""
        try:
            import win32service
            import win32con
            
            scm = win32service.OpenSCManager(
                None, 
                None, 
                win32service.SC_MANAGER_ENUMERATE_SERVICE
            )
            
            services = win32service.EnumServicesStatus(scm)
            
            for service in services:
                service_name, display_name, status = service
                service_id = f"service_{service_name}"
                
                if service_id not in self.known_persistence:
                    service_info = self.get_service_details(scm, service_name)
                    
                    if self.is_suspicious_service(service_info):
                        self.handle_new_persistence(
                            "service",
                            service_id,
                            service_info
                        )
                        self.known_persistence.add(service_id)
                        
            win32service.CloseServiceHandle(scm)
            
        except Exception as e:
            logging.error(f"Service check failed: {e}")
    
    def is_suspicious_service(self, service_info: Dict) -> bool:
        """Determine if a service is suspicious"""
        suspicious_indicators = [
            # Service running from temp or unusual locations
            r'.*\\temp\\.*',
            r'.*\\appdata\\.*',
            r'.*\\users\\.*',
            
            # Suspicious service names
            r'.*update.*',
            r'.*security.*',
            r'.*windows.*defender.*',
            
            # No description or company name
            lambda s: not s.get('description'),
            lambda s: not s.get('company'),
            
            # Weak permissions
            lambda s: s.get('permissions', {}).get('everyone_write', False)
        ]
        
        service_path = service_info.get('binary_path', '').lower()
        
        for indicator in suspicious_indicators:
            if callable(indicator):
                if indicator(service_info):
                    return True
            elif re.search(indicator, service_path, re.IGNORECASE):
                return True
        
        return False
    
    def is_suspicious_task(self, task_info: Dict) -> bool:
        """Determine if a scheduled task is suspicious"""
        suspicious_triggers = [
            'logon', 'startup', 'idle', 'session connect'
        ]
        
        # Check for hidden tasks
        if task_info.get('hidden', False):
            return True
        
        # Check for suspicious triggers
        for trigger in task_info.get('triggers', []):
            if any(st in str(trigger).lower() for st in suspicious_triggers):
                return True
        
        # Check for suspicious actions (like running scripts)
        for action in task_info.get('actions', []):
            action_cmd = action.get('command', '').lower()
            if any(cmd in action_cmd for cmd in ['powershell', 'cmd', 'wscript', 'mshta']):
                return True
        
        return False
    
    def handle_new_persistence(self, persistence_type: str, persistence_id: str, details: Dict):
        """Handle detection of new persistence mechanism"""
        event_data = {
            "event_type": "persistence_detection",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "HIGH",
            "data": {
                "persistence_type": persistence_type,
                "persistence_id": persistence_id,
                "details": details,
                "confidence": 0.8,
                "recommendation": "Investigate and remove if unauthorized"
            }
        }
        
        self.event_callback(event_data)
        
        logging.warning(
            f"New persistence mechanism detected: {persistence_type} - {persistence_id}"
        )
    
    def load_known_persistence(self):
        """Load known legitimate persistence mechanisms"""
        # This would load from a known-good database
        # For now, we'll start with an empty set
        pass
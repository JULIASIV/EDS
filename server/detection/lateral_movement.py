# server/detection/lateral_movement.py
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set
from collections import defaultdict

class LateralMovementDetector:
    def __init__(self, db_session):
        self.db = db_session
        self.suspicious_commands = {
            'psexec': ['psexec', 'psexecsvc', 'psexec.exe'],
            'wmic': ['wmic', 'wmic.exe'],
            'schtasks': ['schtasks', 'schtasks.exe'],
            'sc': ['sc', 'sc.exe'],
            'net': ['net', 'net.exe', 'net1.exe'],
            'at': ['at', 'at.exe'],
            'powershell_remoting': ['winrm', 'enter-pssession', 'invoke-command'],
            'smbexec': ['smbexec'],
            'winexe': ['winexe']
        }
        
        self.detected_movements = set()
        self.network_shares = defaultdict(set)
    
    async def analyze_for_lateral_movement(self, events: List[Dict]) -> List[Dict]:
        """Analyze events for lateral movement indicators"""
        results = []
        
        # Group events by endpoint and time window
        events_by_endpoint = self.group_events_by_endpoint(events)
        
        for endpoint_id, endpoint_events in events_by_endpoint.items():
            # Check for common lateral movement patterns
            patterns = [
                self.detect_remote_execution(endpoint_events),
                self.detect_pass_the_hash(endpoint_events),
                self.detect_smb_lateral_movement(endpoint_events),
                self.detect_rdp_lateral_movement(endpoint_events),
                self.detect_wmi_lateral_movement(endpoint_events)
            ]
            
            for pattern_result in patterns:
                if pattern_result['detected']:
                    results.append({
                        'endpoint_id': endpoint_id,
                        'movement_type': pattern_result['type'],
                        'confidence': pattern_result['confidence'],
                        'evidence': pattern_result['evidence'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'recommendation': pattern_result['recommendation']
                    })
        
        return results
    
    def detect_remote_execution(self, events: List[Dict]) -> Dict:
        """Detect remote execution attempts"""
        evidence = []
        confidence = 0.0
        
        for event in events:
            if event.get('event_type') == 'process_creation':
                process_name = event.get('data', {}).get('process_name', '').lower()
                command_line = event.get('data', {}).get('command_line', '').lower()
                
                # Check for remote execution tools
                for tool, indicators in self.suspicious_commands.items():
                    if any(indicator in process_name or indicator in command_line 
                          for indicator in indicators):
                        evidence.append(f"Remote execution tool detected: {tool}")
                        confidence = max(confidence, 0.7)
                
                # Check for remote command execution patterns
                remote_patterns = [
                    r'\\\\[^\\]+\\[cC]\\$',  # Remote admin share access
                    r'/node:',  # WMI remote execution
                    r'-computername',  # PowerShell remoting
                    r'invoke-command.*-computername',  # PowerShell remoting
                ]
                
                for pattern in remote_patterns:
                    if re.search(pattern, command_line):
                        evidence.append(f"Remote execution pattern: {pattern}")
                        confidence = max(confidence, 0.8)
        
        return {
            'detected': len(evidence) > 0,
            'type': 'remote_execution',
            'confidence': confidence,
            'evidence': evidence,
            'recommendation': 'Block remote execution tools and investigate source'
        }
    
    def detect_pass_the_hash(self, events: List[Dict]) -> Dict:
        """Detect Pass-the-Hash attack patterns"""
        evidence = []
        confidence = 0.0
        
        # Look for unusual authentication patterns
        for event in events:
            if event.get('event_type') == 'network_connection':
                data = event.get('data', {})
                
                # Check for SMB connections followed by remote execution
                if (data.get('remote_port') == 445 and  # SMB port
                    data.get('protocol') == 'TCP'):
                    
                    # Look for subsequent remote execution from same process
                    process_name = data.get('process_name', '')
                    if self.is_system_process(process_name):
                        evidence.append(f"SMB connection from system process: {process_name}")
                        confidence = max(confidence, 0.6)
        
        return {
            'detected': len(evidence) > 2,  # Need multiple indicators
            'type': 'pass_the_hash',
            'confidence': confidence,
            'evidence': evidence,
            'recommendation': 'Investigate for credential theft and lateral movement'
        }
    
    def detect_smb_lateral_movement(self, events: List[Dict]) -> Dict:
        """Detect SMB-based lateral movement"""
        evidence = []
        confidence = 0.0
        
        smb_events = [e for e in events 
                     if e.get('data', {}).get('remote_port') == 445]
        
        if len(smb_events) > 5:  # Multiple SMB connections
            evidence.append(f"Multiple SMB connections: {len(smb_events)}")
            confidence = 0.6
            
            # Check for admin share access
            for event in smb_events:
                command_line = event.get('data', {}).get('command_line', '')
                if any(share in command_line for share in ['C$', 'ADMIN$', 'IPC$']):
                    evidence.append("Admin share access detected")
                    confidence = max(confidence, 0.8)
        
        return {
            'detected': len(evidence) > 0,
            'type': 'smb_lateral_movement',
            'confidence': confidence,
            'evidence': evidence,
            'recommendation': 'Restrict SMB access and monitor admin share usage'
        }
    
    def detect_rdp_lateral_movement(self, events: List[Dict]) -> Dict:
        """Detect RDP-based lateral movement"""
        evidence = []
        confidence = 0.0
        
        rdp_events = [e for e in events 
                     if e.get('data', {}).get('remote_port') == 3389]
        
        if rdp_events:
            evidence.append(f"RDP connections detected: {len(rdp_events)}")
            confidence = 0.5
            
            # Check for multiple RDP sessions in short time
            if len(rdp_events) > 3:
                evidence.append("Multiple RDP sessions indicating hopping")
                confidence = max(confidence, 0.7)
        
        return {
            'detected': len(evidence) > 0,
            'type': 'rdp_lateral_movement',
            'confidence': confidence,
            'evidence': evidence,
            'recommendation': 'Monitor RDP usage and implement RDP restrictions'
        }
    
    def detect_wmi_lateral_movement(self, events: List[Dict]) -> Dict:
        """Detect WMI-based lateral movement"""
        evidence = []
        confidence = 0.0
        
        for event in events:
            if event.get('event_type') == 'process_creation':
                command_line = event.get('data', {}).get('command_line', '').lower()
                process_name = event.get('data', {}).get('process_name', '').lower()
                
                # WMI execution patterns
                wmi_patterns = [
                    r'wmic.*/node:',
                    r'win32_process.*create',
                    r'get-wmiobject.*-computername',
                    r'invoke-wmimethod'
                ]
                
                for pattern in wmi_patterns:
                    if re.search(pattern, command_line):
                        evidence.append(f"WMI remote execution: {pattern}")
                        confidence = max(confidence, 0.8)
        
        return {
            'detected': len(evidence) > 0,
            'type': 'wmi_lateral_movement',
            'confidence': confidence,
            'evidence': evidence,
            'recommendation': 'Restrict WMI access and monitor remote WMI usage'
        }
    
    def is_system_process(self, process_name: str) -> bool:
        """Check if process is a system process that shouldn't make network connections"""
        system_processes = [
            'lsass.exe', 'services.exe', 'winlogon.exe',
            'csrss.exe', 'smss.exe', 'svchost.exe'
        ]
        return process_name.lower() in system_processes
    
    def group_events_by_endpoint(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by endpoint ID"""
        grouped = defaultdict(list)
        for event in events:
            endpoint_id = event.get('agent_id')
            if endpoint_id:
                grouped[endpoint_id].append(event)
        return grouped
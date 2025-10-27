# agent/monitors/process_monitor.py
import threading
import time
import win32process
import win32security
import win32con
import win32api
import psutil
from datetime import datetime

class ProcessMonitor:
    def __init__(self, event_callback, config):
        self.event_callback = event_callback
        self.config = config
        self.running = False
        self.thread = None
        self.known_processes = set()
        
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def monitor_loop(self):
        while self.running:
            try:
                self.scan_processes()
                time.sleep(self.config.process_scan_interval)
            except Exception as e:
                logging.error(f"Process monitor error: {e}")
                time.sleep(5)
    
    def scan_processes(self):
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'username', 'create_time', 'cmdline']):
            try:
                process_info = self.get_detailed_process_info(proc)
                if process_info:
                    current_pids.add(proc.info['pid'])
                    
                    # Check if this is a new process
                    if proc.info['pid'] not in self.known_processes:
                        self.detect_suspicious_behavior(process_info)
                        self.event_callback({
                            "event_type": "process_creation",
                            "data": process_info
                        })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for terminated processes
        terminated_pids = self.known_processes - current_pids
        for pid in terminated_pids:
            self.event_callback({
                "event_type": "process_termination",
                "data": {"pid": pid}
            })
        
        self.known_processes = current_pids
    
    def get_detailed_process_info(self, proc):
        """Get detailed process information using Windows API"""
        try:
            # Get process handle
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False, proc.info['pid']
            )
            
            # Get process token for security context
            token_handle = win32security.OpenProcessToken(
                handle, 
                win32con.TOKEN_QUERY
            )
            
            # Get token information
            token_info = win32security.GetTokenInformation(
                token_handle, 
                win32security.TokenIntegrityLevel
            )
            
            integrity_level = "Unknown"
            if token_info:
                sid = token_info.GetSidSubAuthorityCount()
                if sid > 0:
                    integrity_level_id = token_info.GetSidSubAuthority(sid - 1)
                    integrity_levels = {
                        0x0000: "Untrusted",
                        0x1000: "Low",
                        0x2000: "Medium",
                        0x3000: "High",
                        0x4000: "System"
                    }
                    integrity_level = integrity_levels.get(integrity_level_id, "Unknown")
            
            win32api.CloseHandle(handle)
            
            return {
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "parent_pid": proc.info['ppid'],
                "command_line": " ".join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                "username": proc.info['username'],
                "integrity_level": integrity_level,
                "create_time": datetime.fromtimestamp(proc.info['create_time']).isoformat(),
                "binary_path": proc.exe() if hasattr(proc, 'exe') else "Unknown"
            }
            
        except Exception as e:
            logging.debug(f"Could not get detailed info for PID {proc.info['pid']}: {e}")
            return None
    
    def detect_suspicious_behavior(self, process_info):
        """Detect potentially malicious process behavior"""
        suspicious_patterns = [
            # Office applications spawning command lines
            {"parent": "winword.exe", "child": "cmd.exe"},
            {"parent": "excel.exe", "child": "powershell.exe"},
            {"parent": "outlook.exe", "child": "mshta.exe"},
            
            # System processes spawning scripts
            {"parent": "svchost.exe", "child": "wscript.exe"},
            {"parent": "services.exe", "child": "regsvr32.exe"},
            
            # LOLBAS patterns
            {"parent": "msbuild.exe", "child": "cmd.exe"},
            {"parent": "installutil.exe", "child": "powershell.exe"}
        ]
        
        for pattern in suspicious_patterns:
            if (process_info.get('parent_name', '').lower() == pattern['parent'] and
                process_info['name'].lower() == pattern['child']):
                
                process_info['is_suspicious'] = True
                process_info['suspicion_reason'] = f"Suspicious parent-child: {pattern}"
                break
# agent/monitors/memory_scanner.py
import threading
import time
import psutil
import logging
from datetime import datetime
from agent.detection.yara_scanner import YARAScanner

class MemoryScanner:
    def __init__(self, event_callback, config):
        self.event_callback = event_callback
        self.config = config
        self.running = False
        self.thread = None
        self.yara_scanner = YARAScanner(config.yara_rules_path)
        self.scanned_processes = set()
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.scan_loop, daemon=True)
        self.thread.start()
        logging.info("Memory Scanner started")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logging.info("Memory Scanner stopped")
    
    def scan_loop(self):
        """Periodically scan process memory for malware"""
        while self.running:
            try:
                self.scan_all_processes()
                time.sleep(self.config.memory_scan_interval)
            except Exception as e:
                logging.error(f"Memory scanner error: {e}")
                time.sleep(30)
    
    def scan_all_processes(self):
        """Scan all running processes for malware signatures"""
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                pid = proc.info['pid']
                
                # Skip system processes and already scanned processes
                if pid < 100 or pid in self.scanned_processes:
                    continue
                
                # Scan process memory
                matches = self.yara_scanner.scan_process_memory(pid)
                
                if matches:
                    self.handle_malware_detection(proc, matches)
                
                self.scanned_processes.add(pid)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def handle_malware_detection(self, proc, yara_matches):
        """Handle malware detection event"""
        event_data = {
            "event_type": "malware_detection",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "CRITICAL",
            "data": {
                "pid": proc.info['pid'],
                "process_name": proc.info['name'],
                "yara_matches": yara_matches,
                "memory_usage": proc.info['memory_info'].rss if proc.info['memory_info'] else 0,
                "action_taken": "alert"  # Could be "quarantine", "terminate", etc.
            }
        }
        
        self.event_callback(event_data)
        
        # Log the detection
        logging.critical(
            f"Malware detected in process {proc.info['name']} (PID: {proc.info['pid']}): "
            f"{[match['rule'] for match in yara_matches]}"
        )
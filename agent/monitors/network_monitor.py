# agent/monitors/network_monitor.py
import threading
import time
import socket
import struct
from ctypes import *
import logging
from datetime import datetime

class NetworkMonitor:
    def __init__(self, event_callback, config):
        self.event_callback = event_callback
        self.config = config
        self.running = False
        self.thread = None
        self.known_connections = set()
        
        # Load Windows IP Helper API
        self.iphlpapi = windll.iphlpapi
        
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.thread.start()
        logging.info("Network Monitor started")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logging.info("Network Monitor stopped")
    
    def monitor_loop(self):
        """Monitor network connections using Windows APIs"""
        while self.running:
            try:
                self.scan_tcp_connections()
                self.scan_udp_connections()
                time.sleep(self.config.network_scan_interval)
            except Exception as e:
                logging.error(f"Network monitor error: {e}")
                time.sleep(10)
    
    def scan_tcp_connections(self):
        """Scan TCP connections using GetExtendedTcpTable"""
        try:
            # Get TCP table size
            size = wintypes.DWORD()
            result = self.iphlpapi.GetExtendedTcpTable(
                None, 
                ctypes.byref(size), 
                False,
                socket.AF_INET, 
                2,  # TCP_TABLE_OWNER_PID_ALL
                0
            )
            
            # Allocate buffer
            buffer = ctypes.create_string_buffer(size.value)
            
            # Get TCP table
            result = self.iphlpapi.GetExtendedTcpTable(
                buffer, 
                ctypes.byref(size), 
                False,
                socket.AF_INET, 
                2,  # TCP_TABLE_OWNER_PID_ALL
                0
            )
            
            if result == 0:
                self.process_tcp_table(buffer, size.value)
                
        except Exception as e:
            logging.error(f"Error scanning TCP connections: {e}")
    
    def process_tcp_table(self, buffer, size):
        """Process TCP table and detect suspicious connections"""
        # Parse MIB_TCPTABLE_OWNER_PID structure
        num_entries = struct.unpack('I', buffer.raw[:4])[0]
        
        for i in range(num_entries):
            offset = 4 + i * 24  # Size of MIB_TCPROW_OWNER_PID
            
            # Extract connection details
            state = struct.unpack('I', buffer.raw[offset:offset+4])[0]
            local_addr = struct.unpack('I', buffer.raw[offset+4:offset+8])[0]
            local_port = struct.unpack('>H', buffer.raw[offset+8:offset+10])[0]
            remote_addr = struct.unpack('I', buffer.raw[offset+12:offset+16])[0]
            remote_port = struct.unpack('>H', buffer.raw[offset+16:offset+18])[0]
            pid = struct.unpack('I', buffer.raw[offset+20:offset+24])[0]
            
            # Convert IP addresses
            local_ip = socket.inet_ntoa(struct.pack('I', local_addr))
            remote_ip = socket.inet_ntoa(struct.pack('I', remote_addr))
            
            # Check for suspicious connections
            if state == 5:  # TCP_ESTABLISHED
                connection_id = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
                
                if connection_id not in self.known_connections:
                    self.known_connections.add(connection_id)
                    
                    # Get process info
                    process_info = self.get_process_info(pid)
                    
                    # Check for suspicious patterns
                    is_suspicious, reason = self.check_suspicious_connection(
                        remote_ip, remote_port, process_info
                    )
                    
                    event_data = {
                        "event_type": "network_connection",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {
                            "protocol": "TCP",
                            "local_address": f"{local_ip}:{local_port}",
                            "remote_address": f"{remote_ip}:{remote_port}",
                            "state": "ESTABLISHED",
                            "pid": pid,
                            "process_name": process_info.get('name', 'Unknown'),
                            "is_suspicious": is_suspicious,
                            "suspicion_reason": reason
                        }
                    }
                    
                    self.event_callback(event_data)
        
    def check_suspicious_connection(self, remote_ip, remote_port, process_info):
        """Check if connection is suspicious"""
        suspicious_ports = [4444, 1337, 31337, 9999]  # Common malware ports
        suspicious_processes = ["notepad.exe", "svchost.exe"]  # Processes that shouldn't make connections
        
        # Check port
        if remote_port in suspicious_ports:
            return True, f"Connection to known suspicious port {remote_port}"
        
        # Check process
        if process_info.get('name', '').lower() in suspicious_processes:
            return True, f"Suspicious process making network connection: {process_info['name']}"
        
        # Check for connections to known malicious IPs
        if self.is_malicious_ip(remote_ip):
            return True, f"Connection to known malicious IP: {remote_ip}"
        
        return False, ""
    
    def is_malicious_ip(self, ip):
        """Check if IP is in threat intelligence database"""
        # In production, this would query a threat intelligence service
        malicious_ips = ["1.1.1.1", "2.2.2.2"]  # Example malicious IPs
        return ip in malicious_ips
    
    def get_process_info(self, pid):
        """Get process information by PID"""
        try:
            import psutil
            process = psutil.Process(pid)
            return {
                "name": process.name(),
                "pid": pid,
                "exe": process.exe(),
                "cmdline": process.cmdline(),
                "username": process.username()
            }
        except:
            return {"name": "Unknown", "pid": pid}
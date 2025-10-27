# agent/core.py
import threading
import time
import psutil
import logging
from datetime import datetime
from agent.monitors.process_monitor import ProcessMonitor
from agent.monitors.network_monitor import NetworkMonitor
from agent.monitors.file_monitor import FileMonitor
from agent.monitors.registry_monitor import RegistryMonitor
from agent.communication import APIClient
from agent.config import AgentConfig

class EDRAgent:
    def __init__(self):
        self.config = AgentConfig.load_from_file()
        self.api_client = APIClient(self.config)
        self.monitors = []
        self.performance_stats = {
            "events_processed": 0,
            "memory_usage": 0,
            "cpu_usage": 0,
            "last_checkin": None
        }
        self.running = False
        
        # Initialize monitors
        self.setup_monitors()
        
    def setup_monitors(self):
        """Initialize all security monitors"""
        self.monitors.extend([
            ProcessMonitor(self.handle_event, self.config),
            NetworkMonitor(self.handle_event, self.config),
            FileMonitor(self.handle_event, self.config),
            RegistryMonitor(self.handle_event, self.config)
        ])
    
    def handle_event(self, event):
        """Handle security events from all monitors"""
        try:
            # Add agent metadata
            event["agent_id"] = self.config.agent_id
            event["hostname"] = self.config.hostname
            event["received_at"] = datetime.utcnow().isoformat()
            
            # Send to server (with batching in production)
            self.api_client.submit_event(event)
            
            # Update stats
            self.performance_stats["events_processed"] += 1
            
        except Exception as e:
            logging.error(f"Error handling event: {e}")
    
    def start(self):
        """Start the EDR agent"""
        logging.info("Starting EDR Agent...")
        self.running = True
        
        # Register with server
        if not self.api_client.register():
            logging.error("Failed to register agent with server")
            return False
        
        # Start all monitors
        for monitor in self.monitors:
            monitor.start()
        
        # Start background threads
        self.heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        self.performance_thread = threading.Thread(target=self.performance_loop, daemon=True)
        self.heartbeat_thread.start()
        self.performance_thread.start()
        
        logging.info("EDR Agent started successfully")
        return True
    
    def stop(self):
        """Stop the EDR agent gracefully"""
        logging.info("Stopping EDR Agent...")
        self.running = False
        
        # Stop all monitors
        for monitor in self.monitors:
            monitor.stop()
        
        logging.info("EDR Agent stopped")
    
    def heartbeat_loop(self):
        """Send periodic heartbeats to server"""
        while self.running:
            try:
                self.api_client.heartbeat()
                self.performance_stats["last_checkin"] = datetime.utcnow()
            except Exception as e:
                logging.error(f"Heartbeat failed: {e}")
            
            time.sleep(self.config.heartbeat_interval)
    
    def performance_loop(self):
        """Monitor agent performance"""
        while self.running:
            try:
                process = psutil.Process()
                self.performance_stats["memory_usage"] = process.memory_info().rss
                self.performance_stats["cpu_usage"] = process.cpu_percent()
            except Exception as e:
                logging.error(f"Performance monitoring error: {e}")
            
            time.sleep(60)  # Check every minute
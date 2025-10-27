# agent/security/self_protection.py
import os
import sys
import hashlib
import logging
from ctypes import wintypes, windll, byref

class SelfProtection:
    def __init__(self):
        self.original_hash = self.calculate_self_hash()
        self.protected = False
    
    def enable_protection(self):
        """Enable self-protection mechanisms"""
        try:
            # Prevent debugging
            self.anti_debug()
            
            # Validate integrity
            self.validate_integrity()
            
            # Hide process (optional)
            self.hide_process()
            
            self.protected = True
            logging.info("Self-protection enabled")
            
        except Exception as e:
            logging.error(f"Failed to enable self-protection: {e}")
    
    def anti_debug(self):
        """Anti-debugging techniques"""
        # Check for debugger
        if windll.kernel32.IsDebuggerPresent():
            logging.warning("Debugger detected - exiting")
            sys.exit(1)
        
        # Check remote debugger
        debugger_present = wintypes.BOOL()
        if windll.kernel32.CheckRemoteDebuggerPresent(
            windll.kernel32.GetCurrentProcess(), 
            byref(debugger_present)
        ) and debugger_present:
            logging.warning("Remote debugger detected - exiting")
            sys.exit(1)
    
    def validate_integrity(self):
        """Validate agent integrity"""
        current_hash = self.calculate_self_hash()
        if current_hash != self.original_hash:
            logging.critical("Agent integrity compromised - exiting")
            sys.exit(1)
    
    def calculate_self_hash(self):
        """Calculate hash of current executable"""
        try:
            with open(sys.executable, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return "unknown"
    
    def hide_process(self):
        """Hide agent process from standard enumeration"""
        # This would use advanced techniques to make the process
        # less visible to malware and attackers
        pass
    
    def monitor_tampering(self):
        """Monitor for tampering attempts"""
        # Implementation would watch for attempts to
        # terminate, suspend, or modify the agent process
        pass
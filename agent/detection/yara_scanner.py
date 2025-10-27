# agent/detection/yara_scanner.py
import yara
import os
import threading
import logging
from datetime import datetime
from typing import List, Dict, Any

class YARAScanner:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = None
        self.last_compiled = None
        self.lock = threading.Lock()
        self.load_rules()
    
    def load_rules(self):
        """Load and compile YARA rules"""
        try:
            if os.path.isdir(self.rules_path):
                # Compile rules from directory
                rules_files = []
                for root, dirs, files in os.walk(self.rules_path):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            rules_files.append(os.path.join(root, file))
                
                if rules_files:
                    self.rules = yara.compile(filepaths={
                        os.path.basename(f): f for f in rules_files
                    })
                    self.last_compiled = datetime.now()
                    logging.info(f"Loaded {len(rules_files)} YARA rule files")
                else:
                    logging.warning("No YARA rule files found")
            else:
                # Single rules file
                self.rules = yara.compile(filepath=self.rules_path)
                self.last_compiled = datetime.now()
                logging.info("Loaded YARA rules from single file")
                
        except Exception as e:
            logging.error(f"Error loading YARA rules: {e}")
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file with YARA rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(file_path)
            return [{
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [str(s) for s in match.strings]
            } for match in matches]
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return []
    
    def scan_process_memory(self, pid: int) -> List[Dict[str, Any]]:
        """Scan process memory with YARA rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(pid=pid)
            return [{
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [str(s) for s in match.strings]
            } for match in matches]
        except Exception as e:
            logging.error(f"Error scanning process {pid} memory: {e}")
            return []
    
    def scan_buffer(self, buffer: bytes) -> List[Dict[str, Any]]:
        """Scan a memory buffer with YARA rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(data=buffer)
            return [{
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [str(s) for s in match.strings]
            } for match in matches]
        except Exception as e:
            logging.error(f"Error scanning buffer: {e}")
            return []
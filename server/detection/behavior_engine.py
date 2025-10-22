# server/detection/behavior_engine.py
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict, deque

class BehavioralEngine:
    def __init__(self, db_session):
        self.db = db_session
        self.behavior_profiles = {}
        self.anomaly_threshold = 0.8
        self.event_window = timedelta(minutes=30)
        
        # Behavioral patterns to detect
        self.suspicious_patterns = {
            "process_hollowing": {
                "description": "Process hollowing detection",
                "rules": [
                    {"parent": "explorer.exe", "child": "notepad.exe", "suspicion": 0.3},
                    {"parent": "svchost.exe", "child": "cmd.exe", "suspicion": 0.5},
                    {"parent": "services.exe", "child": "powershell.exe", "suspicion": 0.7}
                ]
            },
            "lateral_movement": {
                "description": "Lateral movement detection",
                "rules": [
                    {"process": "psexec.exe", "suspicion": 0.9},
                    {"process": "wmic.exe", "suspicion": 0.6},
                    {"process": "schtasks.exe", "suspicion": 0.5}
                ]
            },
            "data_exfiltration": {
                "description": "Data exfiltration detection", 
                "rules": [
                    {"process": "ftp.exe", "suspicion": 0.4},
                    {"process": "certutil.exe", "suspicion": 0.7},
                    {"process": "bitsadmin.exe", "suspicion": 0.6}
                ]
            }
        }
    
    async def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze event for suspicious behavior"""
        analysis_result = {
            "is_suspicious": False,
            "confidence": 0.0,
            "patterns": [],
            "recommendation": ""
        }
        
        try:
            # Check against known patterns
            for pattern_name, pattern_config in self.suspicious_patterns.items():
                pattern_match = self._check_pattern(event, pattern_config)
                if pattern_match["matched"]:
                    analysis_result["patterns"].append({
                        "name": pattern_name,
                        "description": pattern_config["description"],
                        "confidence": pattern_match["confidence"]
                    })
                    analysis_result["confidence"] = max(
                        analysis_result["confidence"], 
                        pattern_match["confidence"]
                    )
            
            # Check for anomalies
            anomaly_score = await self._check_anomaly(event)
            analysis_result["confidence"] = max(
                analysis_result["confidence"], 
                anomaly_score
            )
            
            # Determine if suspicious
            analysis_result["is_suspicious"] = (
                analysis_result["confidence"] >= self.anomaly_threshold
            )
            
            # Generate recommendation
            if analysis_result["is_suspicious"]:
                analysis_result["recommendation"] = self._generate_recommendation(
                    event, analysis_result["patterns"]
                )
            
            return analysis_result
            
        except Exception as e:
            logging.error(f"Error in behavioral analysis: {e}")
            return analysis_result
    
    def _check_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> Dict:
        """Check event against a specific pattern"""
        result = {"matched": False, "confidence": 0.0}
        
        for rule in pattern_config["rules"]:
            match_found = True
            
            # Check each condition in the rule
            for key, value in rule.items():
                if key == "suspicion":
                    continue
                    
                if key not in event.get("data", {}) or event["data"][key] != value:
                    match_found = False
                    break
            
            if match_found:
                result["matched"] = True
                result["confidence"] = max(result["confidence"], rule.get("suspicion", 0.0))
        
        return result
    
    async def _check_anomaly(self, event: Dict[str, Any]) -> float:
        """Check if event is anomalous based on historical behavior"""
        try:
            endpoint_id = event.get("agent_id")
            event_type = event.get("event_type")
            
            if not endpoint_id or not event_type:
                return 0.0
            
            # Get historical behavior for this endpoint
            behavior_profile = await self._get_behavior_profile(endpoint_id)
            
            # Check frequency anomaly
            frequency_score = self._check_frequency_anomaly(
                event, behavior_profile, event_type
            )
            
            # Check timing anomaly  
            timing_score = self._check_timing_anomaly(event, behavior_profile)
            
            # Check sequence anomaly
            sequence_score = self._check_sequence_anomaly(event, behavior_profile)
            
            return max(frequency_score, timing_score, sequence_score)
            
        except Exception as e:
            logging.error(f"Error in anomaly detection: {e}")
            return 0.0
    
    def _check_frequency_anomaly(self, event, behavior_profile, event_type):
        """Check if event frequency is anomalous"""
        # Implementation would compare current event frequency
        # against historical baseline
        return 0.0
    
    def _check_timing_anomaly(self, event, behavior_profile):
        """Check if event timing is anomalous"""
        # Implementation would check if event occurs at unusual times
        return 0.0
    
    def _check_sequence_anomaly(self, event, behavior_profile):
        """Check if event sequence is anomalous"""
        # Implementation would check event sequences
        return 0.0
    
    async def _get_behavior_profile(self, endpoint_id):
        """Get or create behavior profile for endpoint"""
        if endpoint_id not in self.behavior_profiles:
            self.behavior_profiles[endpoint_id] = {
                "event_counts": defaultdict(int),
                "event_timings": deque(maxlen=1000),
                "event_sequences": defaultdict(list),
                "last_updated": datetime.utcnow()
            }
        
        return self.behavior_profiles[endpoint_id]
    
    def _generate_recommendation(self, event, patterns):
        """Generate security recommendation"""
        if not patterns:
            return "Investigate suspicious activity"
        
        pattern_names = [p["name"] for p in patterns]
        
        if "process_hollowing" in pattern_names:
            return "Terminate suspicious process and investigate parent process"
        elif "lateral_movement" in pattern_names:
            return "Isolate endpoint and investigate for lateral movement"
        elif "data_exfiltration" in pattern_names:
            return "Block outbound connections and investigate data loss"
        else:
            return "Investigate suspicious behavior"
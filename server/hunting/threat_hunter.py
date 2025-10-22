# server/hunting/threat_hunter.py
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

class HuntingTechnique(Enum):
    PROCESS_INJECTION = "process_injection"
    LIVEOFF_THE_LAND = "liveoff_the_land"
    MEMORY_ANOMALY = "memory_anomaly"
    NETWORK_C2 = "network_c2"
    PERSISTENCE = "persistence"

@dataclass
class HuntingRule:
    name: str
    technique: HuntingTechnique
    description: str
    query: str  # Could be SQL, EQL, etc.
    severity: str
    confidence: float
    enabled: bool

class ThreatHunter:
    def __init__(self, db_session):
        self.db = db_session
        self.hunting_rules: List[HuntingRule] = []
        self.load_hunting_rules()
    
    def load_hunting_rules(self):
        """Load threat hunting rules"""
        self.hunting_rules = [
            HuntingRule(
                name="Process Hollowing Detection",
                technique=HuntingTechnique.PROCESS_INJECTION,
                description="Detects process hollowing by comparing image base addresses",
                query="""
                SELECT * FROM process_events 
                WHERE parent_process_name IN ('explorer.exe', 'svchost.exe')
                AND process_name IN ('notepad.exe', 'calc.exe')
                AND integrity_level = 'Medium'
                """,
                severity="HIGH",
                confidence=0.7,
                enabled=True
            ),
            HuntingRule(
                name="LOLBAS Usage",
                technique=HuntingTechnique.LIVEOFF_THE_LAND,
                description="Detects use of Living Off the Land Binaries and Scripts",
                query="""
                SELECT * FROM process_events 
                WHERE process_name IN ('msbuild.exe', 'installutil.exe', 'regsvr32.exe')
                AND command_line LIKE '%.xml' OR command_line LIKE '%.scf'
                """,
                severity="MEDIUM", 
                confidence=0.6,
                enabled=True
            ),
            HuntingRule(
                name="DNS Tunneling Detection",
                technique=HuntingTechnique.NETWORK_C2,
                description="Detects potential DNS tunneling activity",
                query="""
                SELECT * FROM network_events 
                WHERE remote_port = 53 
                AND process_name NOT IN ('svchost.exe', 'dns.exe')
                AND data_length > 1000
                """,
                severity="HIGH",
                confidence=0.8,
                enabled=True
            ),
            HuntingRule(
                name="Unusual Service Installations",
                technique=HuntingTechnique.PERSISTENCE,
                description="Detects service installations from unusual locations",
                query="""
                SELECT * FROM process_events 
                WHERE process_name = 'sc.exe'
                AND command_line LIKE '%create%'
                AND command_line LIKE '%temp%'
                """,
                severity="HIGH",
                confidence=0.7,
                enabled=True
            )
        ]
    
    async def run_hunting_campaign(self, timeframe_hours: int = 24) -> List[Dict]:
        """Run all enabled hunting rules"""
        results = []
        start_time = datetime.utcnow() - timedelta(hours=timeframe_hours)
        
        for rule in self.hunting_rules:
            if not rule.enabled:
                continue
            
            try:
                rule_results = await self.execute_hunting_rule(rule, start_time)
                results.extend(rule_results)
                
                logging.info(f"Hunting rule '{rule.name}' found {len(rule_results)} results")
                
            except Exception as e:
                logging.error(f"Hunting rule '{rule.name}' failed: {e}")
        
        return results
    
    async def execute_hunting_rule(self, rule: HuntingRule, start_time: datetime) -> List[Dict]:
        """Execute a specific hunting rule"""
        # This would execute the rule's query against the database
        # For now, we'll return mock results
        
        if rule.technique == HuntingTechnique.PROCESS_INJECTION:
            return await self.hunt_process_injection(rule, start_time)
        elif rule.technique == HuntingTechnique.LIVEOFF_THE_LAND:
            return await self.hunt_lolbas(rule, start_time)
        elif rule.technique == HuntingTechnique.NETWORK_C2:
            return await self.hunt_c2_communications(rule, start_time)
        elif rule.technique == HuntingTechnique.PERSISTENCE:
            return await self.hunt_persistence(rule, start_time)
        
        return []
    
    async def hunt_process_injection(self, rule: HuntingRule, start_time: datetime) -> List[Dict]:
        """Hunt for process injection techniques"""
        # Advanced process injection detection
        results = []
        
        # Look for suspicious memory allocations
        suspicious_processes = await self.find_suspicious_memory_operations(start_time)
        results.extend(suspicious_processes)
        
        # Look for remote thread creation
        remote_threads = await self.find_remote_thread_creation(start_time)
        results.extend(remote_threads)
        
        return results
    
    async def hunt_lolbas(self, rule: HuntingRule, start_time: datetime) -> List[Dict]:
        """Hunt for Living Off the Land techniques"""
        results = []
        
        # Check for LOLBAS usage patterns
        lolbas_patterns = [
            # MSBuild executing XML files
            {"process": "msbuild.exe", "pattern": r".*\.xml$"},
            # Regsvr32 executing SCF files
            {"process": "regsvr32.exe", "pattern": r".*\.scf$"},
            # Rundll32 with unusual arguments
            {"process": "rundll32.exe", "pattern": r".*\.dat,.*"},
            # Certutil with decode argument
            {"process": "certutil.exe", "pattern": r".*-decode.*"}
        ]
        
        for pattern in lolbas_patterns:
            matches = await self.find_process_matches(
                pattern["process"], 
                pattern["pattern"], 
                start_time
            )
            results.extend(matches)
        
        return results
    
    async def hunt_c2_communications(self, rule: HuntingRule, start_time: datetime) -> List[Dict]:
        """Hunt for command and control communications"""
        results = []
        
        # Look for beaconing patterns
        beaconing_ips = await self.detect_beaconing(start_time)
        results.extend(beaconing_ips)
        
        # Look for DNS anomalies
        dns_anomalies = await self.detect_dns_anomalies(start_time)
        results.extend(dns_anomalies)
        
        # Look for HTTPS anomalies
        https_anomalies = await self.detect_https_anomalies(start_time)
        results.extend(https_anomalies)
        
        return results
    
    async def detect_beaconing(self, start_time: datetime) -> List[Dict]:
        """Detect beaconing behavior in network traffic"""
        # This would analyze network connections for regular intervals
        # indicating C2 beaconing
        
        results = []
        
        # Look for connections with regular timing
        regular_connections = await self.find_regular_connections(start_time)
        for conn in regular_connections:
            results.append({
                'type': 'beaconing_detected',
                'confidence': 0.7,
                'evidence': f"Regular connections to {conn['remote_ip']} every {conn['interval']} seconds",
                'severity': 'HIGH',
                'recommendation': 'Investigate for C2 communication'
            })
        
        return results
    
    async def detect_dns_anomalies(self, start_time: datetime) -> List[Dict]:
        """Detect DNS-based C2 communications"""
        results = []
        
        # Look for long DNS queries (potential tunneling)
        long_queries = await self.find_long_dns_queries(start_time)
        for query in long_queries:
            results.append({
                'type': 'dns_tunneling_suspected',
                'confidence': 0.6,
                'evidence': f"Long DNS query: {query['query']} ({query['length']} chars)",
                'severity': 'MEDIUM',
                'recommendation': 'Analyze DNS traffic for tunneling'
            })
        
        # Look for unusual DNS record types
        unusual_records = await self.find_unusual_dns_records(start_time)
        for record in unusual_records:
            results.append({
                'type': 'unusual_dns_activity',
                'confidence': 0.5,
                'evidence': f"Unusual DNS record type: {record['type']}",
                'severity': 'LOW',
                'recommendation': 'Monitor DNS activity'
            })
        
        return results
    
    async def find_suspicious_memory_operations(self, start_time: datetime) -> List[Dict]:
        """Find suspicious memory operations indicating injection"""
        # This would query memory operation events
        return []
    
    async def find_remote_thread_creation(self, start_time: datetime) -> List[Dict]:
        """Find remote thread creation events"""
        # This would query thread creation events
        return []
    
    async def find_process_matches(self, process_name: str, pattern: str, start_time: datetime) -> List[Dict]:
        """Find processes matching specific patterns"""
        # This would query process events
        return []
    
    async def find_regular_connections(self, start_time: datetime) -> List[Dict]:
        """Find network connections with regular intervals"""
        # This would analyze connection timing
        return []
    
    async def find_long_dns_queries(self, start_time: datetime) -> List[Dict]:
        """Find unusually long DNS queries"""
        # This would query DNS events
        return []
    
    async def find_unusual_dns_records(self, start_time: datetime) -> List[Dict]:
        """Find unusual DNS record types"""
        # This would query DNS events
        return []
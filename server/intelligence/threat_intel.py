# server/intelligence/threat_intel.py
import asyncio
import aiohttp
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import logging
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatIndicator:
    type: str  # IP, DOMAIN, HASH, URL
    value: str
    threat_level: ThreatLevel
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]

class ThreatIntelligenceEngine:
    def __init__(self):
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.ioc_cache: Dict[str, ThreatIndicator] = {}
        self.suspicious_domains: Set[str] = set()
        self.malicious_ips: Set[str] = set()
        self.known_malware_hashes: Set[str] = set()
        
        # Threat intelligence sources
        self.feeds = {
            "alienvault_otx": "https://otx.alienvault.com/api/v1/",
            "virustotal": "https://www.virustotal.com/vtapi/v2/",
            "abuseipdb": "https://api.abuseipdb.com/api/v2/",
            "malware_bazaar": "https://mb-api.abuse.ch/api/v1/",
            "threatfox": "https://threatfox-api.abuse.ch/api/v1/"
        }
        
        self.load_local_threat_intel()
    
    def load_local_threat_intel(self):
        """Load local threat intelligence databases"""
        try:
            # Load known malicious IPs
            with open('threat_intel/malicious_ips.txt', 'r') as f:
                self.malicious_ips = set(line.strip() for line in f if line.strip())
            
            # Load suspicious domains
            with open('threat_intel/suspicious_domains.txt', 'r') as f:
                self.suspicious_domains = set(line.strip() for line in f if line.strip())
            
            # Load known malware hashes
            with open('threat_intel/malware_hashes.txt', 'r') as f:
                self.known_malware_hashes = set(line.strip() for line in f if line.strip())
                
            logging.info(f"Loaded {len(self.malicious_ips)} malicious IPs, "
                        f"{len(self.suspicious_domains)} suspicious domains, "
                        f"{len(self.known_malware_hashes)} malware hashes")
                        
        except FileNotFoundError:
            logging.warning("Local threat intelligence files not found")
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP reputation across multiple sources"""
        cache_key = f"ip_{ip_address}"
        
        # Check cache first
        if cache_key in self.ioc_cache:
            cached = self.ioc_cache[cache_key]
            if datetime.utcnow() - cached.last_seen < timedelta(hours=1):
                return cached
        
        # Check local database
        if ip_address in self.malicious_ips:
            indicator = ThreatIndicator(
                type="IP",
                value=ip_address,
                threat_level=ThreatLevel.HIGH,
                confidence=0.8,
                source="local_db",
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                tags=["known_malicious"]
            )
            self.ioc_cache[cache_key] = indicator
            return indicator
        
        # Check external sources
        tasks = [
            self._check_abuseipdb(ip_address),
            self._check_virustotal_ip(ip_address)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Find the highest threat level
        max_threat = None
        for result in results:
            if isinstance(result, ThreatIndicator):
                if not max_threat or result.threat_level.value > max_threat.threat_level.value:
                    max_threat = result
        
        if max_threat:
            self.ioc_cache[cache_key] = max_threat
            return max_threat
        
        return None
    
    async def check_file_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """Check file hash against malware databases"""
        cache_key = f"hash_{file_hash}"
        
        if cache_key in self.ioc_cache:
            return self.ioc_cache[cache_key]
        
        # Check local database
        if file_hash in self.known_malware_hashes:
            indicator = ThreatIndicator(
                type="HASH",
                value=file_hash,
                threat_level=ThreatLevel.CRITICAL,
                confidence=0.9,
                source="local_db",
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                tags=["known_malware"]
            )
            self.ioc_cache[cache_key] = indicator
            return indicator
        
        # Check external sources
        tasks = [
            self._check_virustotal_hash(file_hash),
            self._check_malware_bazaar(file_hash)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        max_threat = None
        for result in results:
            if isinstance(result, ThreatIndicator):
                if not max_threat or result.threat_level.value > max_threat.threat_level.value:
                    max_threat = result
        
        if max_threat:
            self.ioc_cache[cache_key] = max_threat
            return max_threat
        
        return None
    
    async def _check_abuseipdb(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP against AbuseIPDB"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Key': self.api_keys['abuseipdb'],
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90
                }
                
                async with session.get(
                    f"{self.feeds['abuseipdb']}check",
                    headers=headers,
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                        
                        if abuse_score > 80:
                            return ThreatIndicator(
                                type="IP",
                                value=ip_address,
                                threat_level=ThreatLevel.HIGH,
                                confidence=abuse_score / 100,
                                source="abuseipdb",
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow(),
                                tags=["high_abuse_score"]
                            )
                        
        except Exception as e:
            logging.debug(f"AbuseIPDB check failed: {e}")
        
        return None
    
    async def _check_virustotal_ip(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP against VirusTotal"""
        # Implementation for VirusTotal API
        pass
    
    async def _check_virustotal_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """Check file hash against VirusTotal"""
        # Implementation for VirusTotal API
        pass
    
    async def _check_malware_bazaar(self, file_hash: str) -> Optional[ThreatIndicator]:
        """Check file hash against MalwareBazaar"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    'query': 'get_info',
                    'hash': file_hash
                }
                
                async with session.post(
                    self.feeds['malware_bazaar'],
                    data=data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        if result.get('query_status') == 'ok':
                            return ThreatIndicator(
                                type="HASH",
                                value=file_hash,
                                threat_level=ThreatLevel.CRITICAL,
                                confidence=0.95,
                                source="malware_bazaar",
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow(),
                                tags=["malware_bazaar_detected"]
                            )
                        
        except Exception as e:
            logging.debug(f"MalwareBazaar check failed: {e}")
        
        return None
    
    def add_custom_ioc(self, indicator: ThreatIndicator):
        """Add custom indicator of compromise"""
        key = f"{indicator.type}_{indicator.value}"
        self.indicators[key] = indicator
        
        # Update local databases
        if indicator.type == "IP" and indicator.threat_level.value >= ThreatLevel.MEDIUM.value:
            self.malicious_ips.add(indicator.value)
        
        elif indicator.type == "HASH" and indicator.threat_level.value >= ThreatLevel.MEDIUM.value:
            self.known_malware_hashes.add(indicator.value)
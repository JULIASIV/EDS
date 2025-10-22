# server/ai/anomaly_detector.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import asyncio
from collections import defaultdict, deque

class AIAnomalyDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.behavior_profiles = {}
        self.anomaly_threshold = 0.75
        
        # Initialize models for different event types
        self.initialize_models()
    
    def initialize_models(self):
        """Initialize machine learning models"""
        # Process behavior model
        self.models['process'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Network behavior model  
        self.models['network'] = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        
        # File activity model
        self.models['file'] = DBSCAN(eps=0.5, min_samples=10)
        
        # Scaler for feature normalization
        self.scalers['process'] = StandardScaler()
        self.scalers['network'] = StandardScaler()
        self.scalers['file'] = StandardScaler()
        
        # TF-IDF for command line analysis
        self.models['command_line'] = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
    
    async def analyze_behavior(self, events: List[Dict]) -> List[Dict]:
        """Analyze events for behavioral anomalies"""
        results = []
        
        for event in events:
            try:
                event_type = event.get('event_type', '')
                if event_type not in self.models:
                    continue
                
                # Extract features
                features = self.extract_features(event)
                if not features:
                    continue
                
                # Detect anomalies
                anomaly_score, is_anomaly = await self.detect_anomaly(event_type, features)
                
                if is_anomaly:
                    result = {
                        'event': event,
                        'anomaly_score': anomaly_score,
                        'is_anomaly': True,
                        'detection_method': 'behavioral_analysis',
                        'confidence': min(anomaly_score, 1.0),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    results.append(result)
                    
            except Exception as e:
                logging.error(f"Behavior analysis error: {e}")
        
        return results
    
    def extract_features(self, event: Dict) -> List[float]:
        """Extract features from event for ML analysis"""
        event_type = event.get('event_type')
        data = event.get('data', {})
        
        if event_type == 'process_creation':
            return self.extract_process_features(data)
        elif event_type == 'network_connection':
            return self.extract_network_features(data)
        elif event_type == 'file_operation':
            return self.extract_file_features(data)
        
        return []
    
    def extract_process_features(self, data: Dict) -> List[float]:
        """Extract features from process creation event"""
        features = []
        
        # Process characteristics
        process_name = data.get('process_name', '').lower()
        parent_process = data.get('parent_process_name', '').lower()
        command_line = data.get('command_line', '')
        
        # Feature 1: Process name entropy (obfuscation detection)
        features.append(self.calculate_entropy(process_name))
        
        # Feature 2: Parent-child relationship score
        features.append(self.calculate_relationship_score(process_name, parent_process))
        
        # Feature 3: Command line length (obfuscation indicator)
        features.append(len(command_line))
        
        # Feature 4: Number of command line arguments
        features.append(len(command_line.split()))
        
        # Feature 5: Suspicious string patterns in command line
        features.append(self.detect_suspicious_patterns(command_line))
        
        # Feature 6: Process timing (off-hours execution)
        features.append(self.calculate_timing_anomaly(data.get('timestamp')))
        
        return features
    
    def extract_network_features(self, data: Dict) -> List[float]:
        """Extract features from network connection event"""
        features = []
        
        remote_ip = data.get('remote_address', '').split(':')[0]
        remote_port = data.get('remote_port', 0)
        process_name = data.get('process_name', '').lower()
        
        # Feature 1: Port unusualness
        features.append(self.calculate_port_anomaly(remote_port, process_name))
        
        # Feature 2: Geographic anomaly (if IP geolocation available)
        features.append(self.calculate_geo_anomaly(remote_ip))
        
        # Feature 3: Protocol anomaly
        features.append(self.calculate_protocol_anomaly(data.get('protocol', ''), process_name))
        
        # Feature 4: Connection frequency
        features.append(self.calculate_connection_frequency(remote_ip, process_name))
        
        # Feature 5: Data transfer pattern
        features.append(self.calculate_data_pattern(data))
        
        return features
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        entropy = 0.0
        text_length = len(text)
        
        for char in set(text):
            p_x = float(text.count(char)) / text_length
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy
    
    def calculate_relationship_score(self, process: str, parent: str) -> float:
        """Calculate suspiciousness of parent-child process relationship"""
        suspicious_pairs = {
            ('svchost.exe', 'cmd.exe'): 0.8,
            ('explorer.exe', 'powershell.exe'): 0.7,
            ('winword.exe', 'cmd.exe'): 0.9,
            ('excel.exe', 'powershell.exe'): 0.9,
            ('outlook.exe', 'mshta.exe'): 0.95
        }
        
        return suspicious_pairs.get((parent, process), 0.0)
    
    def detect_suspicious_patterns(self, command_line: str) -> float:
        """Detect suspicious patterns in command line"""
        patterns = [
            r'powershell.*-enc',
            r'cmd.*/c',
            r'regsvr32.*/s.*scrobj',
            r'mshta.*javascript',
            r'rundll32.*.scr,',
            r'wscript.*.vbs',
            r'certutil.*-decode',
            r'bitsadmin.*/transfer'
        ]
        
        score = 0.0
        command_lower = command_line.lower()
        
        for pattern in patterns:
            if re.search(pattern, command_lower):
                score += 0.2
        
        return min(score, 1.0)
    
    async def detect_anomaly(self, event_type: str, features: List[float]) -> Tuple[float, bool]:
        """Detect anomaly using ML models"""
        try:
            if event_type not in self.models or not self.models[event_type]:
                return 0.0, False
            
            # Scale features
            features_array = np.array(features).reshape(1, -1)
            scaled_features = self.scalers[event_type].transform(features_array)
            
            # Predict anomaly
            if hasattr(self.models[event_type], 'decision_function'):
                # Isolation Forest
                anomaly_scores = self.models[event_type].decision_function(scaled_features)
                anomaly_score = 1 - (1 / (1 + np.exp(-anomaly_scores[0])))  # Convert to 0-1 scale
            else:
                # DBSCAN or other models
                prediction = self.models[event_type].fit_predict(scaled_features)
                anomaly_score = 1.0 if prediction[0] == -1 else 0.0
            
            is_anomaly = anomaly_score > self.anomaly_threshold
            
            return anomaly_score, is_anomaly
            
        except Exception as e:
            logging.error(f"Anomaly detection error: {e}")
            return 0.0, False
    
    async def train_models(self, training_data: List[Dict]):
        """Train ML models with historical data"""
        try:
            # Group events by type
            events_by_type = defaultdict(list)
            for event in training_data:
                event_type = event.get('event_type')
                if event_type:
                    events_by_type[event_type].append(event)
            
            # Train each model
            for event_type, events in events_by_type.items():
                if event_type not in self.models:
                    continue
                
                # Extract features
                features = [self.extract_features(event) for event in events]
                features = [f for f in features if f]  # Remove empty feature lists
                
                if len(features) < 10:  # Need minimum data
                    continue
                
                # Convert to numpy array
                features_array = np.array(features)
                
                # Fit scaler
                self.scalers[event_type].fit(features_array)
                scaled_features = self.scalers[event_type].transform(features_array)
                
                # Train model
                if hasattr(self.models[event_type], 'fit'):
                    self.models[event_type].fit(scaled_features)
                
                logging.info(f"Trained {event_type} model with {len(features)} samples")
                
        except Exception as e:
            logging.error(f"Model training error: {e}")
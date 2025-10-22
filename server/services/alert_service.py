# server/services/alert_service.py
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any
from server.websocket import manager

class AlertService:
    def __init__(self, db_session):
        self.db = db_session
        self.alert_count = 0
    
    async def create_alert(self, event_data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Create and broadcast a security alert"""
        try:
            alert = {
                "id": self.alert_count + 1,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_data.get("event_type"),
                "severity": self._calculate_severity(analysis_result),
                "endpoint_id": event_data.get("agent_id"),
                "description": self._generate_alert_description(event_data, analysis_result),
                "confidence": analysis_result.get("confidence", 0.0),
                "patterns": analysis_result.get("patterns", []),
                "recommendation": analysis_result.get("recommendation", ""),
                "status": "new"
            }
            
            self.alert_count += 1
            
            # Broadcast to all dashboard clients
            await manager.broadcast_to_type({
                "type": "alert",
                "data": alert
            }, "dashboard")
            
            # Log the alert
            logging.warning(
                f"Security Alert: {alert['description']} "
                f"(Confidence: {alert['confidence']:.2f})"
            )
            
            # Store in database
            await self._store_alert(alert)
            
            # Send external notifications
            await self._send_external_notifications(alert)
            
            return alert
            
        except Exception as e:
            logging.error(f"Error creating alert: {e}")
    
    def _calculate_severity(self, analysis_result: Dict[str, Any]) -> str:
        """Calculate alert severity based on confidence score"""
        confidence = analysis_result.get("confidence", 0.0)
        
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"
    
    def _generate_alert_description(self, event_data: Dict, analysis_result: Dict) -> str:
        """Generate human-readable alert description"""
        event_type = event_data.get("event_type", "unknown")
        patterns = [p["name"] for p in analysis_result.get("patterns", [])]
        
        if patterns:
            return f"Suspicious {event_type} activity detected: {', '.join(patterns)}"
        else:
            return f"Anomalous {event_type} activity detected"
    
    async def _store_alert(self, alert: Dict[str, Any]):
        """Store alert in database"""
        # Implementation would store alert in PostgreSQL
        pass
    
    async def _send_external_notifications(self, alert: Dict[str, Any]):
        """Send external notifications (Slack, Email, etc.)"""
        if alert["severity"] in ["high", "critical"]:
            # Send Slack notification
            await self._send_slack_alert(alert)
            
            # Send email notification
            if alert["severity"] == "critical":
                await self._send_email_alert(alert)
    
    async def _send_slack_alert(self, alert: Dict[str, Any]):
        """Send alert to Slack"""
        try:
            # Implementation would use Slack webhook
            pass
        except Exception as e:
            logging.error(f"Error sending Slack alert: {e}")
    
    async def _send_email_alert(self, alert: Dict[str, Any]):
        """Send alert via email"""
        try:
            # Implementation would use SMTP
            pass
        except Exception as e:
            logging.error(f"Error sending email alert: {e}")
# server/websocket.py
from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
import logging
from datetime import datetime

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_info: Dict[WebSocket, Dict] = {}
    
    async def connect(self, websocket: WebSocket, client_type: str = "dashboard"):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_info[websocket] = {
            "type": client_type,
            "connected_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        logging.info(f"WebSocket client connected: {client_type}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            client_info = self.connection_info.pop(websocket, {})
            logging.info(f"WebSocket client disconnected: {client_info.get('type', 'unknown')}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
            self.connection_info[websocket]["last_activity"] = datetime.utcnow()
        except Exception as e:
            logging.error(f"Error sending WebSocket message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        disconnected = []
        message_str = json.dumps(message)
        
        for connection in self.active_connections:
            try:
                await connection.send_text(message_str)
                self.connection_info[connection]["last_activity"] = datetime.utcnow()
            except Exception as e:
                logging.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    async def broadcast_to_type(self, message: Dict[str, Any], client_type: str):
        """Broadcast message to specific client type"""
        message_str = json.dumps(message)
        disconnected = []
        
        for connection in self.active_connections:
            if self.connection_info.get(connection, {}).get("type") == client_type:
                try:
                    await connection.send_text(message_str)
                    self.connection_info[connection]["last_activity"] = datetime.utcnow()
                except Exception as e:
                    logging.error(f"Error broadcasting to {client_type}: {e}")
                    disconnected.append(connection)
        
        for connection in disconnected:
            self.disconnect(connection)

# Global WebSocket manager
manager = ConnectionManager()

# WebSocket endpoint
@app.websocket("/ws/{client_type}")
async def websocket_endpoint(websocket: WebSocket, client_type: str):
    await manager.connect(websocket, client_type)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages if needed
            manager.connection_info[websocket]["last_activity"] = datetime.utcnow()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
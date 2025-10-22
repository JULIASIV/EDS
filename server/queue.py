# server/queue.py
import asyncio
import aio_pika
import json
import logging
from typing import Callable, Dict, Any
from config.settings import settings

logger = logging.getLogger(__name__)

class MessageQueue:
    def __init__(self):
        self.connection = None
        self.channel = None
        self.queues = {}
        
    async def connect(self):
        """Establish connection to RabbitMQ"""
        try:
            self.connection = await aio_pika.connect_robust(
                settings.RABBITMQ_URL,
                timeout=300
            )
            self.channel = await self.connection.channel()
            
            # Declare exchanges
            await self.channel.declare_exchange(
                "edr.events", 
                aio_pika.ExchangeType.TOPIC,
                durable=True
            )
            await self.channel.declare_exchange(
                "edr.alerts", 
                aio_pika.ExchangeType.FANOUT,
                durable=True
            )
            
            # Declare queues
            self.queues['events'] = await self.channel.declare_queue(
                "event_processing", 
                durable=True
            )
            self.queues['alerts'] = await self.channel.declare_queue(
                "alert_notifications", 
                durable=True
            )
            
            # Bind queues to exchanges
            await self.queues['events'].bind("edr.events", "event.*")
            await self.queues['alerts'].bind("edr.alerts")
            
            logger.info("Message queue connected successfully")
            
        except Exception as e:
            logger.error(f"Failed to connect to message queue: {e}")
            raise
    
    async def publish_event(self, event_type: str, event_data: Dict[str, Any]):
        """Publish an event to the message queue"""
        if not self.channel:
            await self.connect()
            
        message = aio_pika.Message(
            body=json.dumps(event_data).encode(),
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        )
        
        await self.channel.default_exchange.publish(
            message,
            routing_key=f"event.{event_type}",
        )
    
    async def consume_events(self, callback: Callable):
        """Consume events from the queue"""
        if not self.queues['events']:
            await self.connect()
            
        async with self.queues['events'].iterator() as queue_iter:
            async for message in queue_iter:
                async with message.process():
                    try:
                        event_data = json.loads(message.body.decode())
                        await callback(event_data)
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
    
    async def close(self):
        """Close the connection"""
        if self.connection:
            await self.connection.close()

# Global message queue instance
mq = MessageQueue()
# config/settings.py
import os
import secrets
from pydantic import BaseSettings, validator
from typing import List, Optional, Dict, Any
from cryptography.fernet import Fernet

class Settings(BaseSettings):
    # Environment
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Server Configuration
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    WORKER_COUNT: int = 4
    MAX_WORKERS: int = 10
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    FERNET_KEY: str = Fernet.generate_key().decode()
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    AGENT_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_HASH_ROUNDS: int = 12
    
    # Database
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_PASSWORD: Optional[str] = None
    
    # Message Queue
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672/"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    AGENT_RATE_LIMIT_PER_MINUTE: int = 50
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["https://edr.yourcompany.com"]
    
    # Agent Configuration
    AGENT_CHECKIN_INTERVAL: int = 30
    HEARTBEAT_INTERVAL: int = 60
    AGENT_REGISTRATION_TOKEN: str = secrets.token_urlsafe(32)
    
    # Data Retention
    EVENT_RETENTION_DAYS: int = 90
    ALERT_RETENTION_DAYS: int = 365
    
    # File Upload
    MAX_FILE_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100MB
    
    # Monitoring
    METRICS_ENABLED: bool = True
    METRICS_PORT: int = 9090
    
    # Alerting
    SLACK_WEBHOOK_URL: Optional[str] = None
    EMAIL_NOTIFICATIONS: bool = False
    SMTP_SERVER: Optional[str] = None
    
    # Detection
    YARA_RULES_PATH: str = "/etc/edr/yara_rules"
    ML_MODEL_PATH: str = "/etc/edr/models"
    
    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        if not v.startswith(("postgresql://", "postgres://")):
            raise ValueError("Database URL must be a PostgreSQL connection string")
        return v

    class Config:
        env_file = ".env.production"
        case_sensitive = True
        secrets_dir = "/run/secrets"

settings = Settings()
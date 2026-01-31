"""
Secrets Management Module.

Provides a centralized interface for retrieving configuration from environment variables.
"""

import os
from typing import Optional, Dict

# =============================================================================
# Core Secret Retrieval
# =============================================================================

def get_secret(path: str, key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve a secret/config from environment variables.
    
    Args:
        path: The 'path' concept (kept for compatibility), e.g., 'secret/database'
        key: The key within the secret, e.g., 'url'
        default: Default value if not found
        
    Returns:
        The environment variable value or default
    """
    # Construct env var name: e.g. secret/database -> DATABASE_URL
    category = path.split('/')[-1].upper()
    env_key = f"{category}_{key.upper()}"
    return os.getenv(env_key, default)


def get_secrets(path: str) -> Dict[str, str]:
    """
    Retrieve all secrets for a category.
    """
    return {}


# =============================================================================
# Convenience Functions for Common Secrets
# =============================================================================

def get_database_url() -> str:
    """Get the database connection URL."""
    return os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/security_brain")


def get_redis_url() -> str:
    """Get the Redis connection URL."""
    return os.getenv("REDIS_URL", "redis://redis:6379/0")


def get_rabbitmq_url() -> str:
    """Get the RabbitMQ connection URL."""
    return os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672//")


def get_github_token() -> Optional[str]:
    """Get the GitHub personal access token."""
    return os.getenv("GITHUB_TOKEN")


def get_gitlab_token() -> Optional[str]:
    """Get the GitLab personal access token."""
    return os.getenv("GITLAB_TOKEN")


def get_llm_config() -> Dict[str, str]:
    """Get all LLM configuration values."""
    return {
        "base_url": os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1"),
        "api_key": os.getenv("LLM_API_KEY", ""),
        "model": os.getenv("LLM_MODEL", "qwen/qwen3-coder:free"),
        "max_tokens": os.getenv("LLM_MAX_TOKENS", "10000"),
        "temperature": os.getenv("LLM_TEMPERATURE", "0.1"),
        "timeout": os.getenv("LLM_TIMEOUT", "600"),
        "max_retries": os.getenv("LLM_MAX_RETRIES", "2"),
    }


def get_ai_api_key() -> str:
    """Get the AI API key."""
    return os.getenv("AI_API_KEY", "token")


def get_container_image(lang: str) -> str:
    """Get the container image for a specific language."""
    defaults = {
        "python": "python:3.9-slim",
        "go": "golang:1.23-alpine",
        "node": "node:18-alpine",
        "java": "openjdk:17-slim",
    }
    return os.getenv(f"{lang.upper()}_IMAGE", defaults.get(lang, ""))


def get_setting(key: str, default: str = "") -> str:
    """Get a configuration setting."""
    return os.getenv(key.upper(), default)


def clear_secret_cache():
    """No-op for env vars."""
    pass

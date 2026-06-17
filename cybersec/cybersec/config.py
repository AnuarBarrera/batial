import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
GEMINI_AUDIT_MODEL: str = os.getenv("GEMINI_AUDIT_MODEL", "gemini-3.5-flash")
GOOGLE_CLOUD_PROJECT: str = os.getenv("GOOGLE_CLOUD_PROJECT", "agente-cosmic")
GOOGLE_CLOUD_LOCATION: str = os.getenv("GOOGLE_CLOUD_LOCATION", "us-west4")
GEMINI_VERTEX_MODEL: str = os.getenv("GEMINI_VERTEX_MODEL", "gemini-2.5-flash")
GEMINI_VERTEX_AUDIT_MODEL: str = os.getenv("GEMINI_VERTEX_AUDIT_MODEL", "gemini-2.5-flash")
ANTHROPIC_VERTEX_PROJECT: str = os.getenv("ANTHROPIC_VERTEX_PROJECT", "agente-cosmic")
ANTHROPIC_VERTEX_REGION: str = os.getenv("ANTHROPIC_VERTEX_REGION", "us-east5")
ANTHROPIC_VERTEX_MODEL: str = os.getenv("ANTHROPIC_VERTEX_MODEL", "claude-sonnet-4-5")
ANTHROPIC_VERTEX_AUDIT_MODEL: str = os.getenv("ANTHROPIC_VERTEX_AUDIT_MODEL", "claude-sonnet-4-5")
OPENAI_COMPAT_BASE_URL: str = os.getenv("OPENAI_COMPAT_BASE_URL", "")
OPENAI_COMPAT_MODEL: str = os.getenv("OPENAI_COMPAT_MODEL", "Qwen/Qwen2.5-Coder-14B-Instruct")
MAILGUN_API_KEY: str = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_SENDER_EMAIL: str = os.getenv("MAILGUN_SENDER_EMAIL", "")
MAILGUN_DOMAIN: str = os.getenv("MAILGUN_DOMAIN", "")

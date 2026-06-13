# cybersec/tests/test_config.py
import os
from importlib import reload
from unittest.mock import patch

def test_config_reads_gemini_key():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-123"}):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.GEMINI_API_KEY == "test-key-123"

def test_config_openai_default_empty():
    clean = {k: v for k, v in os.environ.items() if k != "OPENAI_COMPAT_BASE_URL"}
    with patch.dict(os.environ, clean, clear=True):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.OPENAI_COMPAT_BASE_URL == ""

def test_config_gemini_model_default():
    clean = {k: v for k, v in os.environ.items() if k != "GEMINI_MODEL"}
    with patch.dict(os.environ, clean, clear=True):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.GEMINI_MODEL == "gemini-2.5-flash-lite"

def test_config_gemini_model_override():
    with patch.dict(os.environ, {"GEMINI_MODEL": "gemini-2.5-pro"}):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.GEMINI_MODEL == "gemini-2.5-pro"

def test_config_gemini_audit_model_default():
    clean = {k: v for k, v in os.environ.items() if k != "GEMINI_AUDIT_MODEL"}
    with patch.dict(os.environ, clean, clear=True):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.GEMINI_AUDIT_MODEL == "gemini-2.5-flash"

def test_config_gemini_audit_model_override():
    with patch.dict(os.environ, {"GEMINI_AUDIT_MODEL": "gemini-2.5-pro"}):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.GEMINI_AUDIT_MODEL == "gemini-2.5-pro"

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

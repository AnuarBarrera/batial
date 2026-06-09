from unittest.mock import patch, MagicMock
from cybersec.infrastructure.notifiers.email import MailgunNotifier


def test_sends_email_successfully():
    with patch("cybersec.infrastructure.notifiers.email.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
        notifier = MailgunNotifier(api_key="key", domain="mg.example.com", sender="sec@example.com")
        result = notifier.send(to="admin@example.com", subject="Reporte", body="Contenido")
        assert result is True
        mock_post.assert_called_once()


def test_returns_false_on_error():
    with patch("cybersec.infrastructure.notifiers.email.requests.post") as mock_post:
        mock_post.side_effect = Exception("network error")
        notifier = MailgunNotifier(api_key="key", domain="mg.example.com", sender="sec@example.com")
        result = notifier.send(to="admin@example.com", subject="Reporte", body="Contenido")
        assert result is False

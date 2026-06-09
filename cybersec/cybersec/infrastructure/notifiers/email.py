import logging
import requests

logger = logging.getLogger(__name__)


class MailgunNotifier:
    def __init__(self, api_key: str, domain: str, sender: str):
        self._api_key = api_key
        self._domain = domain
        self._sender = sender

    def send(self, to: str, subject: str, body: str) -> bool:
        try:
            resp = requests.post(
                f"https://api.mailgun.net/v3/{self._domain}/messages",
                auth=("api", self._api_key),
                data={"from": self._sender, "to": to, "subject": subject, "text": body},
                timeout=15,
            )
            resp.raise_for_status()
            logger.info(f"Email enviado a {to}")
            return True
        except Exception as e:
            logger.error(f"Error enviando email a {to}: {e}")
            return False

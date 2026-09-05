"""
Alerting and Webhook Notification Package for Secure SMTP.
"""

from secure_smtp.alerts.engine import AlertEngine, dispatch_alert

__all__ = ["AlertEngine", "dispatch_alert"]

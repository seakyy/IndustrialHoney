"""
Alert System for IndustrialHoney
Sends high-priority Gmails for security incidents
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


class EmailAlerter:
    """
    Sends high-priority security alerts via Google email
    """

    def __init__(self, smtp_server="smtp.gmail.com", port=587):
        self.smtp_server = smtp_server
        self.port = port
        self.sender_email = None
        self.sender_password = None
        self.recipient_email = None
        self.enabled = False

        logger.info("Gmail Alert System initialized")

    def configure(self, sender_email: str, sender_password: str, recipient_email: str):
        """Configure email credentials"""
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_email = recipient_email
        self.enabled = True

        logger.info(f"Email alerts configured: {sender_email} → {recipient_email}")

    def send_security_alert(self, attack_data: Dict[str, Any]) -> bool:
        """
        Send high-priority security alert email
        """
        if not self.enabled:
            logger.warning("Email alerts not configured - skipping")
            return False

        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.recipient_email
            msg[
                'Subject'] = f"CRITICAL: Industrial System Attack Detected - {attack_data.get('attack_type', 'Unknown')}"

            # Set high priority
            msg['X-Priority'] = '1'
            msg['X-MSMail-Priority'] = 'High'
            msg['Importance'] = 'High'

            # Create email body
            body = self._create_alert_body(attack_data)
            msg.attach(MIMEText(body, 'plain'))

            # Send email
            with smtplib.SMTP(self.smtp_server, self.port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            logger.info(f"Security alert sent successfully to {self.recipient_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def _create_alert_body(self, attack_data: Dict[str, Any]) -> str:
        """Create formatted email body"""

        body = f"""
🚨 INDUSTRIAL SECURITY INCIDENT DETECTED 🚨

THREAT SUMMARY:
==============
Time: {attack_data.get('timestamp', datetime.now().isoformat())}
Source IP: {attack_data.get('client_ip', 'Unknown')}
Attack Type: {attack_data.get('attack_type', 'Unknown Attack')}
Target Device: ABB Turbocharger Control Unit (TPL-77K)
Severity: HIGH RISK

ATTACK DETAILS:
==============
"""

        # Add specific details based on attack type
        if 'register' in attack_data:
            body += f"Target Register: {attack_data['register']}\n"
            body += f"Malicious Value: {attack_data['value']}\n"

        if 'function_code' in attack_data:
            body += f"Function Code: {attack_data['function_code']}\n"
            body += f"Description: {attack_data.get('description', 'N/A')}\n"

        body += f"""

RECOMMENDED ACTIONS:
===================
1. Investigate source IP: {attack_data.get('client_ip', 'Unknown')}
2. Check firewall logs for similar activities
3. Review network access controls
4. Consider blocking source IP if malicious
5. Notify industrial security team immediately

SYSTEM INFORMATION:
==================
Honeypot: IndustrialHoney v1.0
Device: ABB Turbocharger Control Unit
Protocol: Modbus TCP
Detection: Real-time industrial threat monitoring

This is an automated alert from IndustrialHoney.
For more information, contact your cybersecurity team.

---
IndustrialHoney Industrial Control Systems Security
Protecting critical infrastructure 24/7
        """

        return body.strip()

    def test_connection(self) -> bool:
        """Test email configuration"""
        if not self.enabled:
            logger.error("Email not configured")
            return False

        try:
            with smtplib.SMTP(self.smtp_server, self.port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)

            logger.info("Email configuration test successful")
            return True

        except Exception as e:
            logger.error(f"Email configuration test failed: {e}")
            return False
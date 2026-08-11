import asyncio
import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from datetime import datetime


class Notifier:
    """Dispatch alerts via WhatsApp, Email, and Slack."""
    
    def __init__(self, config_path: str = "config/notifier_config.json"):
        self.config = self._load_config(config_path)
        self.enabled_channels = self.config.get("enabled_channels", [])
        print(f"[+] Notifier initialized. Channels: {', '.join(self.enabled_channels)}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load notifier configuration."""
        if not os.path.exists(config_path):
            print(f"[!] Notifier config not found: {config_path}")
            return {"enabled_channels": []}
        
        with open(config_path, "r") as f:
            return json.load(f)
    
    async def send(self, alert: Dict):
        """Send alert to all configured channels."""
        tasks = []
        
        if "email" in self.enabled_channels:
            tasks.append(self._send_email(alert))
        
        if "slack" in self.enabled_channels:
            tasks.append(self._send_slack(alert))
        
        if "whatsapp" in self.enabled_channels:
            tasks.append(self._send_whatsapp(alert))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_email(self, alert: Dict):
        """Send alert via email SMTP."""
        try:
            email_config = self.config.get("email", {})
            smtp_host = email_config.get("smtp_host", "")
            smtp_port = email_config.get("smtp_port", 587)
            smtp_user = email_config.get("smtp_user", "")
            smtp_pass = email_config.get("smtp_pass", "")
            to_email = email_config.get("to_email", "")
            
            if not all([smtp_host, smtp_user, smtp_pass, to_email]):
                print("[!] Email config incomplete, skipping email alert")
                return
            
            subject = f"[{alert['severity'].upper()}] {alert['rule_name']} - 5G Core Alert"
            body = self._format_email_body(alert)
            
            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))
            
            # Send email in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._smtp_send,
                smtp_host, smtp_port, smtp_user, smtp_pass,
                smtp_user, to_email, msg
            )
            print(f"[+] Email sent: {subject}")
            
        except Exception as e:
            print(f"[!] Failed to send email: {e}")
    
    def _smtp_send(self, host, port, user, password, sender, recipient, msg):
        """Send email via SMTP (blocking, run in executor)."""
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(sender, [recipient], msg.as_string())
    
    async def _send_slack(self, alert: Dict):
        """Send alert to Slack webhook."""
        try:
            slack_config = self.config.get("slack", {})
            webhook_url = slack_config.get("webhook_url", "")
            
            if not webhook_url:
                print("[!] Slack webhook URL not configured")
                return
            
            color_map = {
                "critical": "#dc3545",
                "warning": "#ffc107",
                "info": "#17a2b8"
            }
            
            payload = {
                "text": f"5G Core Alert: {alert['rule_name']}",
                "attachments": [
                    {
                        "color": color_map.get(alert["severity"], "#36a64f"),
                        "title": alert["rule_name"],
                        "text": alert["message"],
                        "fields": [
                            {"title": "Severity", "value": alert["severity"].upper(), "short": True},
                            {"title": "Node", "value": alert["node"], "short": True},
                            {"title": "Interface", "value": alert["interface"], "short": True},
                            {"title": "Count", "value": str(alert["count"]), "short": True},
                            {"title": "Time", "value": alert["timestamp"], "short": False}
                        ]
                    }
                ]
            }
            
            # Use requests if available, otherwise skip
            try:
                import requests
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: requests.post(webhook_url, json=payload, timeout=5)
                )
                print(f"[+] Slack alert sent: {alert['rule_name']}")
            except ImportError:
                print("[!] requests not installed, skipping Slack alert")
            
        except Exception as e:
            print(f"[!] Failed to send Slack alert: {e}")
    
    async def _send_whatsapp(self, alert: Dict):
        """Send alert via WhatsApp Business API."""
        try:
            whatsapp_config = self.config.get("whatsapp", {})
            phone_number_id = whatsapp_config.get("phone_number_id", "")
            access_token = whatsapp_config.get("access_token", "")
            to_number = whatsapp_config.get("to_number", "")
            
            if not all([phone_number_id, access_token, to_number]):
                print("[!] WhatsApp config incomplete, skipping WhatsApp alert")
                return
            
            # Format message for WhatsApp
            message = f"*5G Core Alert [{alert['severity'].upper()}]*\n\n"
            message += f"*{alert['rule_name']}*\n"
            message += f"{alert['message']}\n\n"
            message += f"Node: {alert['node']} | Interface: {alert['interface']}\n"
            message += f"Time: {alert['timestamp']}"
            
            payload = {
                "messaging_product": "whatsapp",
                "to": to_number,
                "type": "text",
                "text": {"body": message}
            }
            
            url = f"https://graph.facebook.com/v18.0/{phone_number_id}/messages"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            try:
                import requests
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: requests.post(url, json=payload, headers=headers, timeout=5)
                )
                print(f"[+] WhatsApp alert sent: {alert['rule_name']}")
            except ImportError:
                print("[!] requests not installed, skipping WhatsApp alert")
            
        except Exception as e:
            print(f"[!] Failed to send WhatsApp alert: {e}")
    
    def _format_email_body(self, alert: Dict) -> str:
        """Format alert as HTML email body."""
        color_map = {
            "critical": "#dc3545",
            "warning": "#ffc107",
            "info": "#17a2b8"
        }
        bg_color = color_map.get(alert["severity"], "#36a64f")
        
        html = f"""
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: #1e1e1e; padding: 30px; border-radius: 12px; border: 1px solid #333;">
                <div style="background: {bg_color}; color: white; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <h2 style="margin: 0;">{alert['severity'].upper()}: {alert['rule_name']}</h2>
                </div>
                <div style="margin-bottom: 20px;">
                    <p style="font-size: 16px; line-height: 1.6;">{alert['message']}</p>
                </div>
                <div style="background: #252525; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr><td style="padding: 8px; color: #888;"><strong>Node</strong></td><td style="padding: 8px;">{alert['node']}</td></tr>
                        <tr><td style="padding: 8px; color: #888;"><strong>Interface</strong></td><td style="padding: 8px;">{alert['interface']}</td></tr>
                        <tr><td style="padding: 8px; color: #888;"><strong>Count</strong></td><td style="padding: 8px;">{alert['count']}</td></tr>
                        <tr><td style="padding: 8px; color: #888;"><strong>Time</strong></td><td style="padding: 8px;">{alert['timestamp']}</td></tr>
                    </table>
                </div>
                <div style="font-size: 12px; color: #666; text-align: center;">
                    5G Core Alert Correlator - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
                </div>
            </div>
        </body>
        </html>
        """
        return html

    async def send_license_email(self, to_email: str, license_text: str, plan: str, transaction_id: str):
        """Send LICENSE-ENTERPRISE.txt to customer after payment."""
        try:
            email_config = self.config.get("email", {})
            smtp_host = email_config.get("smtp_host", "")
            smtp_port = email_config.get("smtp_port", 587)
            smtp_user = email_config.get("smtp_user", "")
            smtp_pass = email_config.get("smtp_pass", "")
            
            if not all([smtp_host, smtp_user, smtp_pass]):
                print("[!] Email config incomplete, skipping license email")
                return
            
            subject = f"Your 5G Core Analyzer {plan.title()} License - Transaction {transaction_id}"
            
            html_body = f"""
            <html>
            <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: #1e1e1e; padding: 30px; border-radius: 12px; border: 1px solid #333;">
                    <div style="background: #51cf66; color: white; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                        <h2 style="margin: 0;">Payment Confirmed - License Activated</h2>
                    </div>
                    <div style="margin-bottom: 20px;">
                        <p style="font-size: 16px; line-height: 1.6;">
                            Thank you for purchasing the <strong>{plan.title()}</strong> license for 5G Core Analyzer.
                            Your payment has been confirmed and your license is attached below.
                        </p>
                    </div>
                    <div style="background: #252525; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                        <h3 style="color: #51cf66; margin-top: 0;">License Details</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr><td style="padding: 8px; color: #888;"><strong>Plan</strong></td><td style="padding: 8px;">{plan.title()}</td></tr>
                            <tr><td style="padding: 8px; color: #888;"><strong>Transaction ID</strong></td><td style="padding: 8px;">{transaction_id}</td></tr>
                            <tr><td style="padding: 8px; color: #888;"><strong>License Type</strong></td><td style="padding: 8px;">Commercial / Production</td></tr>
                        </table>
                    </div>
                    <div style="background: #252525; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                        <h3 style="color: #ffc107; margin-top: 0;">LICENSE-ENTERPRISE.txt</h3>
                        <pre style="background: #121212; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px;">{license_text}</pre>
                    </div>
                    <div style="font-size: 12px; color: #666; text-align: center;">
                        Questions? Contact support@Memo2782.github.io
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(html_body, "html"))
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._smtp_send,
                smtp_host, smtp_port, smtp_user, smtp_pass,
                smtp_user, to_email, msg
            )
            print(f"[+] License email sent to {to_email} for plan {plan}")
            
        except Exception as e:
            print(f"[!] Failed to send license email: {e}")

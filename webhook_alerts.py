"""
Webhook Alert Module
====================
Sends alerts to Slack (or any webhook) when critical threats are detected.
Uses standard HTTP POST — no Slack SDK needed.
"""

import requests
import json
import datetime
import os


class WebhookAlerter:

    def __init__(self):
        # Optional: global webhook from environment variable
        self.default_webhook = os.environ.get('SLACK_WEBHOOK_URL', '')

    def send_slack_alert(self, webhook_url, scan_type, target, risk_level, risk_score, risk_factors):
        """
        Send a formatted Slack alert for a critical threat.
        """
        if not webhook_url:
            return {'success': False, 'error': 'No webhook URL provided'}

        # Choose emoji based on risk
        if risk_score >= 80:
            emoji = '🚨'
            color = '#991b1b'
        elif risk_score >= 60:
            emoji = '⚠️'
            color = '#dc2626'
        else:
            emoji = '💡'
            color = '#d97706'

        # Build Slack message payload
        factors_text = '\n'.join([f'• {f}' for f in risk_factors[:5]])
        if len(risk_factors) > 5:
            factors_text += f'\n• ...and {len(risk_factors) - 5} more'

        payload = {
            'attachments': [
                {
                    'color': color,
                    'blocks': [
                        {
                            'type': 'header',
                            'text': {
                                'type': 'plain_text',
                                'text': f'{emoji} {risk_level} Threat Detected'
                            }
                        },
                        {
                            'type': 'section',
                            'fields': [
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Type:*\n{scan_type.title()}'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Threat Score:*\n{risk_score}/100'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Target:*\n`{target[:80]}`'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Time:*\n{datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC")}'
                                }
                            ]
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'*Risk Factors:*\n{factors_text}'
                            }
                        },
                        {
                            'type': 'context',
                            'elements': [
                                {
                                    'type': 'mrkdwn',
                                    'text': 'Sent by *Phishing Intelligence Platform v5.0*'
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                return {'success': True, 'message': 'Alert sent to Slack successfully'}
            else:
                return {
                    'success': False,
                    'error': f'Slack returned status {response.status_code}: {response.text}'
                }

        except requests.Timeout:
            return {'success': False, 'error': 'Webhook request timed out'}
        except requests.ConnectionError:
            return {'success': False, 'error': 'Could not connect to webhook URL'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def send_generic_webhook(self, webhook_url, data):
        """
        Send raw JSON to any webhook endpoint.
        """
        try:
            response = requests.post(
                webhook_url,
                json=data,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def test_webhook(self, webhook_url):
        """
        Send a test message to verify the webhook works.
        """
        payload = {
            'text': '✅ *Phishing Intelligence Platform* webhook connected successfully! You will receive alerts here when critical threats are detected.'
        }
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            if response.status_code == 200:
                return {'success': True, 'message': 'Test message sent successfully'}
            else:
                return {'success': False, 'error': f'Webhook returned {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


_alerter = None

def get_webhook_alerter():
    global _alerter
    if _alerter is None:
        _alerter = WebhookAlerter()
    return _alerter

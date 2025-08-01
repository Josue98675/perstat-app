import os
import requests

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
FROM_EMAIL = 'noreply@yourdomain.com'  # You can verify a real email too

def send_reminder_email(to_email, name):
    subject = "PERSTAT Reminder"
    content = f"Hi {name}, don't forget to submit your PERSTAT for tomorrow."

    data = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": FROM_EMAIL},
        "subject": subject,
        "content": [{"type": "text/plain", "value": content}]
    }

    response = requests.post(
        'https://api.sendgrid.com/v3/mail/send',
        headers={
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        },
        json=data
    )

    return response.status_code == 202

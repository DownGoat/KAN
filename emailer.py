__author__ = 'Sindre Smistad'

import smtplib
import sys
import logging
import datetime
from email.mime.text import MIMEText


abuse_msg = """
Abuse from: %s
Between %s and %s we have received %d login attempts from the above mentioned IP address on our honeypot, of them %d
were successful login attempts.

Often these types of attacks come from computers compromised, and are being used to compromised additional computers.
We send you this e-mail in hopes that your company/organization will notify the right people that they might have been
compromised and do not know it.

This is a automated e-mail, but any responses will be read.
"""

module_logger = logging.getLogger('KAN.emailer')


def send_email(to, _from, password, attack):
    _from += "@gmail.com"
    msg = MIMEText(abuse_msg % (
        attack.ip,
        datetime.datetime.fromtimestamp(attack.first_seen).strftime('%Y-%m-%d %H:%M:%S'),
        datetime.datetime.fromtimestamp(attack.last_seen).strftime('%Y-%m-%d %H:%M:%S'),
        attack.attempts,
        len(attack.tty_logs)
    ))

    msg["Subject"] = "Abuse from %s" % attack.ip
    msg["From"] = _from
    msg["To"] = to

    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.ehlo()
    s.starttls()
    s.login(msg['From'], password)
    s.send_message(msg)

    module_logger.info("E-mail sent to %s", to)

    return attack
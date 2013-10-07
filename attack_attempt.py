__author__ = 'Sindre Smistad'
import logging
import datetime


class AttackAttempt():
    """
    This class is used to represent a "attack" agains the honeypot, it records the IP, number of attempts and any
    created tty logs. It is also used to store some other data that is not directly from the log, like any abuse emails
    for that address.
    """
    def __init__(self, ip=None, first_seen=None, last_seen=None, attempts=None, tty_logs=[], sent_notifications=0,
                 abuse_emails=[]):
        self.ip = ip
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.attempts = attempts
        self.tty_logs = tty_logs
        self.sent_notifications = sent_notifications
        self.abuse_emails = abuse_emails

    def update_attack(self, attempt):
        """
        This updates some stuff about the attack, like first/last seen, attempts, tty logs. This is usually called when
        a new line in the log is parsed, and the IP is previously known.

        :param attempt: Another attack object, with the data that needs updated.
        """
        if len(attempt.tty_logs) and attempt.tty_logs not in self.tty_logs:
            self.tty_logs.append(attempt.tty_logs)

        self.attempts += 1

        if attempt.first_seen < self.first_seen:
            self.first_seen = attempt.first_seen

        if attempt.last_seen > self.last_seen:
            self.last_seen = attempt.last_seen

    def json_ready(self):
        """
        Turns the object into a dict that can be turned to json by the json module.

        :return: A dict populated with this objects data.
        """
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attempts": self.attempts,
            "tty_logs": self.tty_logs,
            "sent_notifications": self.sent_notifications,
            "abuse_emails": self.abuse_emails,
        }

    def __str__(self):
        last_seen = datetime.datetime.fromtimestamp(self.last_seen).strftime('%Y-%m-%d %H:%M:%S')
        first_seen = datetime.datetime.fromtimestamp(self.first_seen).strftime('%Y-%m-%d %H:%M:%S')

        return "%s %s %s %s %s" % (
            self.ip,
            first_seen,
            last_seen,
            self.attempts,
            self.tty_logs
        )



__author__ = 'Sindre Smistad'

import socket
import logging
import time
import datetime

from attack_attempt import AttackAttempt

# create logger
module_logger = logging.getLogger('KAN.log_parser')


def datestring_to_timestamp(datestring):
    """
    Turns the date format found in the kippo log to unix timestamp.

    :param datestring: The date string to turn.

    :return: The date string as unix timestamp.
    """
    ymd_str = datestring.split(" ")[0]
    hms_str = datestring.split(" ")[1]

    tzone = hms_str.split("+")[1]
    hms_str = hms_str.split("+")[0]

    year = int(ymd_str.split("-")[0])
    month = int(ymd_str.split("-")[1])
    day = int(ymd_str.split("-")[2])

    hour = int(hms_str.split(":")[0])
    min = int(hms_str.split(":")[1])
    sec = int(hms_str.split(":")[2])

    dateobj = datetime.datetime(year, month, day, hour, min, sec)

    return time.mktime(dateobj.timetuple())


def extract_data(line, whitelist):
    """
    Extracts the wanted data from a line of the log.

    :param line: The line of data.
    :param whitelist: List of whitelisted IPs.
    :return: If successful it returns a dict with the extracted data. If it fails None is returned.
    """
    data = dict()

    # Really only interested in lines with login attempt data, and opening of new tty logs.
    if "Opening TTY log:" in line or "login attempt" in line:
        pass
    else:
        return None

    #Get the IP
    try:
        splitted = line.split("[")
        splitted = splitted[1].split("]")
        splitted = splitted[0].split(",")
        data["ip"] = splitted[2]
    except IndexError as error:
        module_logger.debug(error)

        return None

    if data["ip"] in whitelist:
        module_logger.info("%s in whitelist" % data["ip"])
        return None

    if "login attempt" in line:
        module_logger.debug("login attempt")
        data["tty_log"] = []
    else:
        module_logger.debug("Open log line.")
        splitted = line.split("Opening TTY log: ")
        splitted = splitted[1].split("/")
        data["tty_log"] = splitted[2]

    # Get the date string and turn it to a unix timestamp.
    ts = datestring_to_timestamp("%s %s" % (line.split(" ")[0], line.split(" ")[1]))
    data["first_seen"] = ts
    data["last_seen"] = ts
    data["attempts"] = 1

    return data


def parse(filename, attack_attempts, whitelist):
    """
    Parses the log file to extract the data doh.

    :param filename: Path to the log file.

    :param attack_attempts: List of AttackAttempts objects.

    :param whitelist: List of whitelisted IPs.

    :return: Returns a list of AtackAttempts objects if successful, returns None if something fails.
    """
    log_file = None

    #The attack attempts will be stored with IP as key, and a AttackAttempt object as the value.

    try:
        log_file = open(filename, "rb")
    except IOError as error:
        module_logger.error(error)

        return None

    for line in log_file:
        line_data = extract_data(line.decode("utf-8").strip(), whitelist)

        if line_data is None:
            continue

        attack_attempt = AttackAttempt(line_data["ip"], line_data["first_seen"], line_data["last_seen"],
                                       line_data["attempts"], line_data["tty_log"])

        #Update already existing attack attempt if there has been one before from this IP.
        if attack_attempt.ip in attack_attempts:
            attack_attempts[attack_attempt.ip].update_attack(attack_attempt)
        else:
            attack_attempts[attack_attempt.ip] = attack_attempt

        module_logger.info("IP %s has been seen %d times between %s and %s" % (
            attack_attempt.ip, attack_attempts[attack_attempt.ip].attempts,
            attack_attempts[attack_attempt.ip].first_seen,
            attack_attempts[attack_attempt.ip].last_seen))

        module_logger.debug(attack_attempts[attack_attempt.ip])

    return attack_attempts


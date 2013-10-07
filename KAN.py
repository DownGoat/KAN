import re

__author__ = 'Sindre Smistad'
__version__ = "0.0.1 first build"

import logging
import log_parser
import json
import emailer
import sys
import argparse
from attack_attempt import AttackAttempt
from ipwhois import IPWhois
from pprint import pprint


print("""
        ####    ####     ####### ########          ####
 +     ####   ####      #### #### #### ####    +   ####
      ####  ####       ####   #### ####  ####      ####
     #### #### +      ####  +  #### ####   ####    ####
    ########         ####       #### ####    ####  ####
   ####  ####       ################# ####     ########
  ####    ####     ####           #### ####      ######
 #### +    ####   ####             #### ####  +   #####
####        #### ####  +            #### ####      ####
      Kippo Abuse Notifier version %s
            Sindre Smistad, sindre@downgoat.net
""" % __version__)


parser = argparse.ArgumentParser(
    description="""Pulling out the IP address of the main kippo log file, and try and e-mail the registrar to notify
    about malicious behaviour.""")

parser.add_argument("kippo", metavar="kippo.log", help="Path to the kippo log file.")
parser.add_argument("email", metavar="email", help="A gmail address to send emails from.")
parser.add_argument("password", metavar="password", help="The e-mail password.")
parser.add_argument("-s", "--save", help="Path to the file to save parsing results too.", default=False)
parser.add_argument("-l", "--load", help="Path to the file to load parsing results from.", default=False)
parser.add_argument("-w", "--whitelist", help="Path to the file that contains whitelisted IPs, they will be ignored.", default=False)
parser.add_argument("-v", "--verbose", help="Debug output.", action="store_true")

args = parser.parse_args()


# create logger with 'spam_application'
logger = logging.getLogger('KAN')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('KAN.log')
if args.verbose:
    fh.setLevel(logging.DEBUG)
else:
    fh.setLevel(logging.INFO)
# create console handler with a higher log level
ch = logging.StreamHandler()
if args.verbose:
    ch.setLevel(logging.DEBUG)
else:
    ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

module_logger = logging.getLogger('KAN')


def save(filename, attacks):
    """
    This function saves the AttackAttempts objects to file. The objects are stored as json, so manually editing, and
    loading them for use later is easy.

    :param filename: The path including the filename of where to save the data.
    :param attacks: The list of AttackAttempts objects.

    :return: Returns False if the something goes wrong, returns True if everything is successful.
    """
    save_file = None
    try:
        open(filename, "w").close()
        save_file = open(filename, "w")
    except IOError as error:
        module_logger.error(error)
        return False

    for key, value in attacks.items():
        attacks[key] = value.json_ready()

    try:
        # Dump the data, set indent options etc to make it more readable for puny humans.
        save_file.write(json.dumps(attacks, sort_keys=True, indent=4, separators=(',', ': ')))
        save_file.close()
    except IOError as error:
        module_logger.error(error)
        return False

    return True


def load(filename):
    """
    This function loads previously stored data, and creates a list of AttackAttempts objects of the data.

    :param filename: Path to the stored data.

    :return: Returns a list of AttackAttempts if successful, returns None if it fails.
    """
    load_file = None
    try:
        load_file = open(filename, "rb")
    except IOError as error:
        module_logger.error(error)

        return None

    try:
        attacks = json.loads(str(load_file.read().decode("utf-8")))
    except ValueError as error:
        module_logger.info("%s was empty." % filename)

        return None

    # Create the objects.
    for key, value in attacks.items():
        attacks[key] = AttackAttempt(
            value["ip"],
            value["first_seen"],
            value["last_seen"],
            value["attempts"],
            value["tty_logs"],
            value["sent_notifications"],
            value["abuse_emails"]
        )

    load_file.close()

    return attacks


def find_abuse_emails(attacks):
    """
    This function is used to lookup whois data for the different IPs, this is done by the help of the ipwhois module.
    Since if the registrars aren't using the same format the parsing of the returned data often misses abuse emails.
    So if the module does not find a address, the function tries to search the raw data with a regex for a e-mail
    address to contact.

    :param attacks: List of the AttackAttempt objects.

    :return: Returns a modified list of the AttackAttempt objects.
    """
    for key, value in attacks.items():
        if len(value.abuse_emails) != 0:
            continue

        obj = IPWhois(value.ip)
        module_logger.info("Looking up whois data on %s" % value.ip)
        results = obj.lookup(inc_raw=True)

        other_emails = []
        abuse_emails = []
        for net in results["nets"]:
            if net["abuse_emails"] is not None:
                abuse_emails.append(net["abuse_emails"])

            if net["misc_emails"] is not None:
                other_emails.append(net["misc_emails"])

            if net["tech_emails"] is not None:
                other_emails.append(net["tech_emails"])

        # If no other e-mails are found try searching the raw data.
        if len(abuse_emails) == 0 and len(other_emails) == 0:
            module_logger.debug("ipwhois parser did not find any emails, trying regex on raw.")
            found = re.findall(r"[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]{2,4}", results["raw"])

            if len(found) != 0:
                abuse_emails = found

        if len(abuse_emails) == 0 and len(other_emails) != 0:
            abuse_emails = other_emails

        attacks[key].abuse_emails = abuse_emails

    return attacks


def open_whitelist(filename):
    """
    This function is used to load a file with whitelisted IPs. To avoid embarrassment if something fails when opening
    and reading the data the program will exit.

    :param filename: Path to the whitelist file.

    :return: Returns a list of whitelisted IPs.
    """
    whitelist = None
    try:
        whitelist = open(filename, "rb")
    except IOError as error:
        module_logger.critical("Whitelist not found:\n %s" % error)
        sys.exit()

    ips = []
    for line in whitelist:
        ips.append(line.decode("utf-8").strip())

    if len(ips) == 0:
        module_logger.critical("Whitelist was empty, exiting.")
        sys.exit()

    return ips


attacks = None
if args.load:
    attacks = load(args.load)

if attacks is None:
    attacks = dict()

whitelist = []
if args.whitelist:
    whitelist = open_whitelist(args.whitelist)

attacks = log_parser.parse(args.kippo, attacks, whitelist)

attacks = find_abuse_emails(attacks)

for key, value in attacks.items():
    if len(value.abuse_emails) != 0 and value.sent_notifications == 0:
        attack = emailer.send_email(value.abuse_emails[0], args.email, args.password, value)
        #attack = emailer.send_email("sindre@downgoat.net", args.email, args.password, value)
        attack.sent_notifications = attack.attempts
        attacks[key] = attack

if args.save:
    if save(args.save, attacks):
        module_logger.info("The attacks were saved to file: %s" % args.save)
    else:
        module_logger.error("Could not write too: %s" % args.save)
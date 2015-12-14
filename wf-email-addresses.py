# -*- encoding: utf-8 -*-

import sys
import cgmail
import logging
import textwrap

from whitefacesdk.client import Client
from whitefacesdk.observable import Observable
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

# this is a crappy work around for using python 2.7.6 that
# ships with Ubuntu 14.04. This is discuraged, see:
# http://urllib3.readthedocs.org/en/latest/security.html#disabling-warnings
import requests
requests.packages.urllib3.disable_warnings()

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'

logger = logging.getLogger(__name__)

WHITEFACE_USER = ''
WHITEFACE_TOKEN = ''
WHITEFACE_FEED = ''


def main():
    """
    A script to extract email addresses in the body of spam email messages and submit the following to
    whiteface:

    * From
    * Subject
    * Description
    * Email Address
    """

    p = ArgumentParser(
        description=textwrap.dedent('''\
        example usage:
            $ cat test.eml | cgmail
            $ cgmail --file test.eml
        '''),
        formatter_class=RawDescriptionHelpFormatter,
        prog='cgmail'
    )

    p.add_argument('-d', '--debug', dest='debug', action="store_true")
    p.add_argument("-f", "--file", dest="file", help="specify email file")

    args = p.parse_args()

    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    console = logging.StreamHandler()
    logging.getLogger('').setLevel(loglevel)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger('').addHandler(console)

    options = vars(args)

    # get email from file or stdin
    if options.get("file"):
        with open(options["file"]) as f:
            email = f.read()
    else:
        email = sys.stdin.read()
        logger.info("wf-email-addresses processing email")


    # Initiate wf client object
    cli = Client(token=WHITEFACE_TOKEN)

    # parse email message
    results = cgmail.parse_email_from_string(email)

    sent_count = 0

    for result in results:
        if result['body_email_addresses']:
            for email_address in result['body_email_addresses']:
                data = {
                    "user": WHITEFACE_USER,
                    "feed": WHITEFACE_FEED,
                    "observable": email_address,
                    "tags": "uce, email-address",
                    "description": "email addresses parsed out of the message body sourced from unsolicited " \
                                   "commercial email (spam)"
                }

                try:
                    ret = Observable(cli, data).submit()
                    if ret['observable']['id']:
                        sent_count += 1
                except Exception as e:
                    raise Exception(e)

    logger.info("sent {0} email addresses to whiteface".format(sent_count))

if __name__ == "__main__":
    main()

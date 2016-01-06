# -*- encoding: utf-8 -*-

import sys
import cgmail
import logging
import textwrap
import json
import re

from whitefacesdk.client import Client
from whitefacesdk.indicator import Indicator
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

# this is a crappy work around for using python 2.7.6 that
# ships with Ubuntu 14.04. This is discuraged, see:
# http://urllib3.readthedocs.org/en/latest/security.html#disabling-warnings
import requests
requests.packages.urllib3.disable_warnings()

WHITEFACE_USER = ''
WHITEFACE_TOKEN = ''
WHITEFACE_FEED = ''

'''
exclude is a list of strings that you want to sanitize before sending 
to whiteface. the list of strings in exclude will be applied to:
 - From Address
 - Subject
 - Email address found in the message body

the string specified will be replaed with "<redacted>". 
'''

# Example: exclude = ['john@example.com', '@test.com']
exclude = []

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
logger = logging.getLogger(__name__)

def find_exclusions(email_address):
    '''

    :param email_address:
    :return:
    '''

    # if exclude is populated
    if exclude:
        # compile a list of regular expresssions
        regexes = [ re.compile(p) for p in exclude]

        for regex in regexes:
            if regex.search(email_address):
                # if an email address is to be excluded
                return True
            else:
                return False
    # if exclude is not populated
    else:
        return False


def sanitize(value):
    '''

    :param value: a string; it is expected to be a email header value (from, subject)

    :return: a string
    '''

    # if exclude is populated
    if exclude:
        # compile a list of regular expresssions
        regexes = [ re.compile(p) for p in exclude]

        for regex in regexes:
            if regex.search(value):
                value = regex.sub('redacted', value)
                break
        return value
    # if exclude is not populated, return the origional value
    else:
        return value

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
        adata = {}
        data = {}
        if result['body_email_addresses']:
            for email_address in result['body_email_addresses']:

                if find_exclusions(email_address):
                    # skip the indicator as it was found in the excludes list
                    logger.info("skipping {0} as it was marked for exclusion".format(email_address))
                    continue
                else:
                    # add from to adata if exists
                    if 'from' in result['headers']:
                        adata['from'] = sanitize(result['headers']['from'][0])
                    # add subject to adata if exists
                    if 'subject' in result['headers']:
                        adata['subject'] = sanitize(result['headers']['subject'][0])

                    data = {
                        "user": WHITEFACE_USER,
                        "feed": WHITEFACE_FEED,
                        "indicator": email_address,
                        "tags": "uce, email-address",
                        "description": "email addresses parsed out of the message body sourced from unsolicited " \
                                       "commercial email (spam)"
                    }

                    # add adata as a comment if populated
                    if adata:
                        comment = json.dumps(adata)
                        data['comment'] = comment

                    try:
                        ret = Indicator(cli, data).submit()
                        if ret['indicator']['id']:
                            sent_count += 1
                    except Exception as e:
                        raise Exception(e)

    logger.info("sent {0} email addresses to whiteface".format(sent_count))

if __name__ == "__main__":
    main()

# wf-email-addresses
A script to submit email addresses seen in the message body of UCE to csirtg.io

## Requirements

1. [py-cgmail](https://github.com/csirtgadgets/py-cgmail)
1. [py-csirtgsdk](https://github.com/csirtgadgets/py-csirtgsdk)

## Goals

1. To demonstrate how to interact with csirtg using the csirtg SDK

## Requirements

1. A [csirtg](https://csirtg.io) account
1. A csirtg account token; within csirtg:
  1. Select your username
  1. Select "tokens"
  1. Select "Generate Token
1. A csirtg feed; within csirtg
  1. Select (the plus sign)
  1. Select Feed
  1. Choose a feed name (e.g. port scanners)
  1. Choose a feed description (hosts blocked in firewall logs)
1. A Linux mail server with procmail installed
  * procmail is only one way this script could be used

## Install

1. Create a [virtual environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/#basic-usage) for this
project.
1. Install [py-cgmail](https://github.com/csirtgadgets/py-cgmail) and [py-csirtgsdk](https://github.com/csirtgadgets/py-csirtgsdk)
within the virtual environment.
1. Download the wf-email-addresses.py script

 ```bash
$ wget https://raw.githubusercontent.com/giovino/wf-email-addresses/master/wf-email-addresses.py
 ```
1. Edit wf-email-addresses.py to fill in (WHITEFACE_USER, WHITEFACE_FEED, WHITEFACE_TOKEN)
1. Leverage procmail to feed spam email through standard in. This is just an example, you will want to customize
it appropriately.

 ```
# Process spam emails to have the email addresses in the message body submitted
# to csirtg
:0 c
* ^X-Spam-Level: \*\*\*\*\*
| /path/to/venv/bin/python2.7 /path/to/wf-email-addresses.py
 ```

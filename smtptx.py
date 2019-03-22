#!/usr/bin/env python
#==============================================================================
# Title        :   SMTPTX
# Dependencies :   Python v2.7 and Python DNS Toolkit (www.dnspython.org)
# Version      :   1.1 Beta
# Author       :   Copyright (c) 2014 <circle@0x90.se>, http://www.0x90.se
# Thanks/Creds :
# Abstract     :   This very simple tool is used for sending simple email and
#                  do some basic email testing from a pentester perspective.
#                  Its able to send messages without depending on an specific
#                  MTA/SMTP server. Unlike tools like sendemail it handles the
#                  MX record resolution itself and connects to the relevant
#                  server and sends the email. Knowing the address of the
#                  specific SMTP server is thus not necessary.
#
# License      :   This code is free and released under the terms of GPL v3
#
# Issues       :   First pre-production == Some issues do exist and functions
#                  ARE missing. It is NOT very fault tolerant at all!
#                  The basic stuff seem to work, no extensive tests has been
#                  done! The code has been tested only on Linux (Debian & Kali)
#
# Todo         :   Near future improvements:
#                  - Ability to accept domain only when resolving SMTP servers
#                    and not rely on a full email address
#                  - Add custom EHLO host, VRFY and the like options
#                  - Add logging to file
#                  - Add 'quiet' option in order to suppress all output
# Todo         :   Later improvements:
#                  - Structure the code in a better manner
#                  - Perhaps add interactive mode
#
# Change log   :   Initial release == Bugs for sure!
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND ANY CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR ANY CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# THIS PROGRAM MAY NOT BE USED IN ANY ILLEGAL ACTIVITIES!
#
#==============================================================================

import sys
import os
import getopt
import time
import re
import smtplib
import email.utils

from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from email import Encoders


def banner():
    print("                                                                           ")
    print("===========================================================================")
    print("  SMTPTX v1.1 Beta by <circle@0x90.se>, http://www.0x90.se         GPL v3  ")
    print("  A small and very simple email testing tool                               ")
    print("===========================================================================")
    print("                                                                           ")


def usage():
    print("                                                                           ")
    print(" -h --help                                                                 ")
    print("  Help section, and you are looking at it                                  ")
    print("                                                                           ")
    print(" -f --from <FROM_ADDRESS>                                                  ")
    print("    If no from address is used, someone@somewhere.com will be used instead ")
    print("                                                                           ")
    print(" -t --to <TO_ADDRESS>                                                      ")
    print("    If no to address is given, the from address will be used (relay test)  ")
    print("                                                                           ")
    print(" -m --message <MESSAGE>                                                    ")
    print("    Plain text or HTML. If no message is given, time and date will be used ")
    print("                                                                           ")
    print(" -s --subject <SUBJECT>                                                    ")
    print("    If no subject is given, the default string \"This is a test\" is used  ")
    print("                                                                           ")
    print(" -a --attachment <FILENAME>                                                ")
    print("    Given in the form of a path: \\path\\to\\file                          ")
    print("                                                                           ")
    print(" -d --dns <IP_ADDRESS>                                                     ")
    print("    Use a custom DNS server for resolving MX records                       ")
    print("                                                                           ")
    print(" -T --dns-timeout <SECONDS>                                                ")
    print("    Set a custom DNS resolution timeout in seconds. Default is 3s          ")
    print("                                                                           ")
    print(" -S --smtp-server <SMTP_SERVER>                                            ")
    print("    Use a specific SMTP server                                             ")
    print("                                                                           ")
    print(" -E --ehlo-host <EHLO_HOST>                                                ")
    print("    Set a custom EHLO host. Default is your local hostname                 ")
    print("                                                                           ")
    print(" -p --smtp-port <PORT>                                                     ")
    print("    Use a non-standard port for the remote SMTP server. Default is 25      ")
    print("                                                                           ")
    print(" -U --username <USERNAME>                                                  ")
    print("    Username for SMTP server authentication                                ")
    print("                                                                           ")
    print(" -P --password <PASSWORD>                                                  ")
    print("    Password for SMTP server authentication                                ")
    print("                                                                           ")
    print(" -r --resolve                                                              ")
    print("    Only resolve SMTP server(s) for a given email address. No email is sent")
    print("    Must be used in conjunction with option: -t                            ")
    print("                                                                           ")
    print(" -v --verbose                                                              ")
    print("    Verbose output. Add extra status messages to standard output           ")
    print("                                                                           ")
    print(" -e --use-tls                                                              ")
    print("    Use encryption capabilities if SMTP server supports it                 ")
    print("                                                                           ")

    return


def resolve_smtp_server(optsData):
    """
    Resolve the MX record of the given email domain name e.g. hotmail.com and
    return a list with SMTP servers. This is kinda dirty since the DNS query returns
    an object and the documentation is missing some information on this.
    Or perhaps its just the ignorant self... ;)
    TODO:
    """
    smtpServers = []

    dnsResolver = dns.resolver.Resolver()

    dnsResolver.timeout = optsData['dnstimeout']
    dnsResolver.lifetime = optsData['dnstimeout']

    if optsData['dns']:
        print (" Using custom DNS Server: %s" % optsData['dns'])
        dnsResolver.nameservers = [optsData['dns']]

    matchDomain = re.match(r'.*@(.*)', optsData['to'], re.M | re.I)
    mailDomain = matchDomain.group(1)

    print (" Resolving MX records for: %s\n" % mailDomain)

    try:
        mxQuery = dns.resolver.query(mailDomain, 'MX')

    except dns.exception.DNSException as dnsError:
        print(" A DNS error was encountered! Reason:\n")
        print(dnsError)
        sys.exit(1)

    print (" Resolved %i SMTP host(s)" % (len(mxQuery)))
    print ("")

    # Populate the hosts list with SMTP servers
    for mxData in mxQuery:
        mxRecord = repr(mxData.exchange)
        mxString = re.match(r'<DNS name (.*)\.>$', mxRecord, re.M | re.I)
        mxHost = mxString.group(1)

        try:
            # Give us the IP address of each MX host
            aQuery = dns.resolver.query(mxHost, 'A')[0].address

        except dns.exception.DNSException as dnsError:
            print(" A DNS error was encountered! Reason:\n")
            print(dnsError)
            sys.exit(1)

        print(" - %s -> %s" % (mxHost, aQuery))
        smtpServers.append(mxHost)

    print("")
    optsData['smtpServer'] = smtpServers[0]

    return


def send_email(optsData):
    """
    Send the email based on the dictionary passed to this function.
    TODO:
    """

    emailMessage = MIMEMultipart()

    emailMessage['To'] = email.utils.formataddr(('', optsData['to']))
    emailMessage['From'] = email.utils.formataddr(('', optsData['from']))
    emailMessage['Subject'] = optsData['subject']

    emailMessage.attach(MIMEText(optsData['message']))

    if optsData['attachment']:
        add_attachment(optsData, emailMessage)

    if optsData['verbose']:
        print (" This is what will be sent:\n")
        print (emailMessage.as_string())

        if optsData['attachment']:
            print (" Attached file: %s\n" % optsData['attachment'])

    try:
        if optsData['verbose']:
            print (" Using SMTP server: %s:%d\n" % (optsData['smtpServer'], optsData['smtpPort']))

        smtpHandler = smtplib.SMTP(optsData['smtpServer'], optsData['smtpPort'])

        smtpHandler.set_debuglevel(optsData['verbose'])

        # We need to perform a EHLO in order to get a list of supported features
        smtpHandler.ehlo(optsData['ehloHost'])

        if optsData['usetls']:
            if smtpHandler.has_extn('STARTTLS'):
                try:
                    print ("\n Server supports TLS, using it...\n")
                    smtpHandler.starttls()

                except smtplib.SMTPException as smtpError:
                    print (" Failure of biblical proportions! Unable to send email. Reason:\n")
                    print (" %s\n" % smtpError)
                    sys.exit(1)
            else:
                print (" Server does not seem to support TLS, skipping...\n")

        # Reidentify over TLS if set up
        smtpHandler.ehlo(optsData['ehloHost'])

        if optsData['username'] and optsData['password']:
            try:
                smtpHandler.login(optsData['username'], optsData['password'])

            except smtplib.SMTPAuthenticationError:
                print(" Authentication failure!\n")
                print(" Will try to ignore...\n")

        smtpHandler.sendmail(optsData['from'], [optsData['to']], emailMessage.as_string())
        smtpHandler.quit()
        print ("\n The email has been sent!\n")

    except smtplib.SMTPException as smtpError:
        print (" Failure of biblical proportions! Unable to send email. Reason:\n")
        print (" %s\n" % smtpError)
        sys.exit(1)

    return


def add_attachment(optsData, emailMessage):
    """
    Add any type of attachment to the email.
    TODO: Add attachment size check?
    """

    part = MIMEBase('application', "octet-stream")

    # part.set_payload(open(optsData['attachment'], "rb").read())
    try:
        attachment = open(optsData['attachment'], "rb")

    # We will exit as a safety precaution as we perhaps don't want to screw up for
    # example a social engineering campaign due to a simple file not found error!
    except IOError as fileError:
        print(" Unable to open the attachment file! Reason:\n")
        print(fileError)
        sys.exit(1)

    part.set_payload(attachment.read())

    Encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename=%s' % os.path.basename(optsData['attachment']))
    emailMessage.attach(part)

    return


def main():
    """
    Main function and argument collector/processor
    TODO:
    """

    optsData = {'to': '',
                'from': 'someone@somewhere.com',
                'subject': 'This is a test',
                'message': time.asctime(time.localtime(time.time())),
                'verbose': False,
                'smtpServer': '',
                'smtpPort': 25,
                'ehloHost': '',
                'dns': '',
                'dnstimeout': 3,
                'resolve': False,
                'attachment': '',
                'username': False,
                'password': False,
                'usetls': False}

    banner()

    try:
        if len(sys.argv) < 2:
            print("Too few arguments supplied...")
            usage()
            sys.exit(1)

        opts, args = getopt.getopt(sys.argv[1:], "hvf:t:m:s:E:d:T:S:p:ra:U:P:e",
                                   ["help",
                                   "verbose",
                                   "from=",
                                   "to=",
                                   "message=",
                                   "subject=",
                                   "ehlo-host=",
                                   "dns=",
                                   "dns-timeout=",
                                   "smtp-server=",
                                   "smtp-port=",
                                   "resolve",
                                   "attachment=",
                                   "username=",
                                   "password=",
                                   "use-tls"])

    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(2)
        elif opt in ('-v', '--verbose'):
            optsData['verbose'] = True
        elif opt in ('-f', '--from'):
            optsData['from'] = arg
        elif opt in ('-t', '--to'):
            optsData['to'] = arg
        elif opt in ('-s', '--subject'):
            optsData['subject'] = arg
        elif opt in ('-m', '--message'):
            optsData['message'] = arg
        elif opt in ('-E', '--ehlo-host'):
            optsData['ehloHost'] = arg
        elif opt in ('-d', '--dns'):
            optsData['dns'] = arg
        elif opt in ('-T', '--dns-timeout'):
            optsData['dnstimeout'] = int(arg)
        elif opt in ('-a', '--attachment'):
            optsData['attachment'] = arg
        elif opt in ('-S', '--smtp-server'):
            optsData['smtpServer'] = arg
        elif opt in ('-p', '--smtp-port'):
            optsData['smtpPort'] = int(arg)
        elif opt in ('-r', '--resolve'):
            optsData['resolve'] = True
        elif opt in ('-U', '--username'):
            optsData['username'] = arg
        elif opt in ('-P', '--password'):
            optsData['password'] = arg
        elif opt in ('-e', '--use-tls'):
            optsData['usetls'] = True
        else:
            usage()
            sys.exit(1)

    if optsData['resolve']:
        if not optsData['to']:
            print(" Error: No recipient address was given!")
            usage()
            sys.exit(1)

        resolve_smtp_server(optsData)
        sys.exit(0)

    elif optsData['smtpServer']:
        send_email(optsData)

    else:
        resolve_smtp_server(optsData)
        send_email(optsData)


if __name__ == "__main__":

    try:
        import dns.resolver
        import dns.exception

    except ImportError:
        print(" Import Error: You seem to be missing the DNS Python library!              ")
        print(" Either check your installation or go to www.pythondns.org                 ")
        print(" Also try using: sudo pip install dnspython                                ")
        sys.exit(1)

    main()

# ---[ EOF ]---
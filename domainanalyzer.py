#!/usr/bin/env python3
# coding=utf-8
"""Analyzes given domainnamne and pressents important information"""
import sys
import socket
from datetime import datetime
import subprocess
import requests
import pythonwhois
import dns
from dns import resolver

# TODO: Highlight important information

UNKNOWN = r'¯\_(ツ)_/¯'
RESOVING_NAMESERVER = '8.8.8.8'

# Get domain name form arguments
DOMAIN = sys.argv[1]

# PROBLEM = sys.argv[2]
# INFORMATION = information(DOMAIN)
# SUGGESTIONS = analyze(INFORMATION, PROBLEM)
# visualize(SUGGESTIONS)

# strip extra domain information
if '//' in DOMAIN:
    DOMAIN = DOMAIN.split("//")[-1].split("/")[0]

# get punycode
try:
    DOMAIN.encode(encoding='utf-8').decode('ascii')
except UnicodeDecodeError:
    DOMAIN_PUNYCODE = DOMAIN.encode("idna").decode("utf-8")
else:
    DOMAIN_PUNYCODE = ''


# resolve against google server to get more accurate whois
RES = resolver.Resolver()
RES.nameservers = [RESOVING_NAMESERVER]


# init ip list for domain
IPS = []

# if domain name is given
if len(sys.argv) > 1:

    # get whois
  
    WHOIS = pythonwhois.get_whois(DOMAIN, True)

    # get php version
    PHP = UNKNOWN
    try:
        RESULT = requests.get('http://{}'.format(DOMAIN))
        try:
            PHP = RESULT.headers['X-Powered-By']
        except KeyError:
            pass
    except:
        pass

    # calculate days left
    DAYSLEFT = (WHOIS['expiration_date'][0].date() - datetime.now().date()).days
    EXP = '' if DAYSLEFT > 66 else 'EXP\t' + WHOIS['expiration_date'][0].strftime("%Y-%m-%d") + ' (' + str(DAYSLEFT) + ' days)'
# calculate hours ago
    try:
        HOURSAGO = round((datetime.now().date() - WHOIS['updated_date'][0].date()).total_seconds() / 3600)
        MOD = '' if HOURSAGO > 48 else 'Mod\t' + WHOIS['updated_date'][0].strftime("%Y-%m-%d") + " (%g hours)" % round(HOURSAGO, 0)
    except KeyError:
        MOD = 'Mod\tN/A'

    print('STATUS\t{}'.format(' '.join(WHOIS['status'])))
    if MOD:
        print(MOD)
    if EXP:
        print(EXP)
    print('REG\t{}'.format(' '.join(WHOIS['registrar'])))
    print('DNS\t{}'.format(' '.join(WHOIS['nameservers'])))
    print('PHP\t{}'.format(PHP))


    # get ip from domain
    try:
        ANSWERS = RES.query(DOMAIN)
        for rdata in ANSWERS:
            IPS.append(rdata.address)
        print('IP\t{}'.format(' / '.join(IPS)))

        # get host from ip
        try:
            HOST = socket.gethostbyaddr(IPS[0])
            print('HOST\t{}'.format(HOST[0]))
        except socket.error:
            print('HOST\t{}'.format(UNKNOWN))

        # get name from ip
        WHOIS_2 = pythonwhois.get_whois(IPS[0], True)
        try:
            print('ORG\t{}'.format(WHOIS_2['contacts']['registrant']['name']))
        except (KeyError, TypeError):
            try:
                print('ORG\t{}'.format(WHOIS_2['emails'][0]))
            except KeyError:
                print('ORG\t{}'.format(UNKNOWN))

    except dns.resolver.NXDOMAIN:
        print('ERR\tNo such domain (NXDOMAIN)')
    except dns.resolver.Timeout:
        print('ERR\tTimeout')
    except dns.exception.DNSException:
        print('ERR\tDNSException')

    MX = subprocess.check_output(['dig', '+noall', '+answer', 'MX', DOMAIN]).decode('unicode_escape').strip().replace('\n','\n\t')
    if MX:
        print('MX\t{}'.format(MX))
    else:
        print('MX\t{}'.format(UNKNOWN))


    print('TXT\t{}'.format(subprocess.check_output(['dig', '+noall', '+answer', 'TXT', DOMAIN]).decode('unicode_escape').strip()))

    if DOMAIN_PUNYCODE:
        print('PUNY\t{}'.format(DOMAIN_PUNYCODE))
    
    # if you want to open domain in browser
    # webbrowser.open('http://' + DOMAIN)

# if you want to do anything cool with a keyword
if len(sys.argv) > 2:
    pass

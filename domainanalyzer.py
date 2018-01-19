#!/usr/bin/env python3
# coding=utf-8
"""Analyzes given domainnamne and pressents important information"""
import sys
import socket
import subprocess
import requests
import pythonwhois
import dns
from dns import resolver

# TODO: fix for ÅÄÖ domains like xn--hlsa-loa.se hälsa.se
# TODO: maybe use subprocess whois instead and parese to avoid pwhois encoding problems
# use chardet and https://github.com/joepie91/python-whois/pull/59 to solv problem in net.py 

# Settings
UNKNOWN = r''
RESOVING_NAMESERVER = '8.8.8.8'

COLOR = {
    'purple': '\033[95m',
    'cyan': '\033[96m',
    'darkcyan': '\033[36m',
    'blue': '\033[94m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'bold': '\033[1m',
    'underline': '\033[4m',
    'end': '\033[0m'
}

def main():
    """Main function"""

    # get the domain from arguments
    domain = get_argument(1, None)

    # get the problem from arguments
    problem = get_argument(2, None)

    # get information about the domain
    information = get_information(domain) if domain else {}

    # get suggestions on how to fix the domains problem
    suggestions = analyze(information, problem) if domain else {}

    # communicate information and suggestions to user
    output_console(information, suggestions)

def analyze(information, problem):
    """Get suggestions what can be fixed"""
    suggestions = []
    # for key, value in information.items():
    #     if(value):
    #         suggestions.append('{}\t {}'.format(key, value))
    #     else:
    #         suggestions.append('{}\t {}'.format(key, UNKNOWN))
    return suggestions


def get_argument(index, return_except):
    """get argument at index or returns return_except"""
    try:
        return sys.argv[index]
    except IndexError:
        return return_except

def get_information(domain):
    """get information about the domain"""

    # prepare domain information dictionary
    information = {}

    # create resolver object
    res = resolver.Resolver()
    res.nameservers = [RESOVING_NAMESERVER]

    # get only domain name
    information['name'] = domain.split("//")[-1].split("/")[0] if '//' in domain else domain
    
    # use only domain name for rest of the script
    domain = information['name']

    # get punycode
    try:
        domain.encode(encoding='utf-8').decode('ascii')
    except UnicodeDecodeError:
        domain_punycode = domain.encode("idna").decode("utf-8")
    else:
        domain_punycode = ''
    information['puny'] = domain_punycode

    # init ip list for domain
    ips = []

    # get whois from domain name
    try:
        whois = pythonwhois.get_whois(domain, True)
    except UnicodeDecodeError:
        whois = False
        information['ERR1'] = 'Python whois UnicodeDecodeError (Domain)'

    # get SSL cert
    try:
        cert = requests.get('https://{}'.format(domain), verify=True)
        information['SSL'] = 'Yes'
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        information['SSL'] = 'No'

    # get php version
    try:
        result = requests.get('http://{}'.format(domain))
        try:
            php = result.headers['X-Powered-By']
        except KeyError:
            php = ''
    except:
        php = ''
    information['php'] = php

    # get expiry date
    try:
        information['exp'] = whois['expiration_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        information['exp'] = ''

    # get modified
    try:
        information['mod'] = whois['updated_date'][0].strftime("%Y-%m-%d %H:%M")
    except (KeyError, TypeError):
        information['mod'] = ''

    # get status
    try:
        status = ' '.join(whois['status'])
    except (KeyError, TypeError):
        status = ''
    information['status'] = status

    try:
        reg = ' '.join(whois['registrar'])
    except (KeyError, TypeError):
        reg = ''
    information['reg'] = reg

    try:
        ns_ = ' '.join(whois['nameservers'])
    except (KeyError, TypeError):
        ns_ = ''
    information['dns'] = ns_

    # get ip from domain
    try:
        answers = res.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        information['ip'] = ' / '.join(ips)

        # get host from ip
        try:
            host = socket.gethostbyaddr(ips[0])[0]
        except socket.error:
            host = ''
        information['host'] = host

        # get name from ip
        try:
            whois_2 = pythonwhois.get_whois(ips[0], True)
        except UnicodeDecodeError:
            whois_2 = False
            information['ERR2'] = 'Python whois UnicodeDecodeError (IP)'
        try:
            org = whois_2['contacts']['registrant']['name']
        except (KeyError, TypeError):
            try:
                org = whois_2['emails'][0]
            except (KeyError, TypeError):
                org = ''
        information['org'] = org

    except dns.resolver.NXDOMAIN:
        information['err'] = 'ERR\tNo such domain (NXDOMAIN)'
    except dns.resolver.Timeout:
        information['err'] = 'ERR\tTimeout'
    except dns.exception.DNSException:
        information['err'] = 'ERR\tDNSException'

    mx_ = subprocess.check_output(['dig', '+noall', '+answer', 'MX', domain]).decode('unicode_escape').strip().replace('\n', '\n\t')
    if mx_:
        information['mx'] = mx_
    else:
        information['mx'] = ''


    information['txt'] = subprocess.check_output(['dig', '+noall', '+answer', 'TXT', domain]).decode('unicode_escape').strip().replace('\n', '\n\t')

    # if you want to open domain in browser
    # webbrowser.open('http://' + DOMAIN)
    return information

def output_console(information, suggestions):
    """output suggestions to console"""
    for key, value in information.items():
        if value:
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], value))
        else:
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], UNKNOWN))
    for suggestion in suggestions:
        print(suggestion)
#test

if __name__ == "__main__":
    main()

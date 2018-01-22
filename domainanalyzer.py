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
import lxml.html
import urllib
import re

# This fix needs to be used on net.py in pythonwhois on your local computer to correctly handle non standard characters
# https://github.com/joepie91/python-whois/pull/59

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
    suggestions = {'errors':[],'varning':[],'notice':[]}

    # varning status
    if('ok' not in information['STAT']):
        suggestions['errors'].append('Status code not OK!')
    
    # notice ssl 
    if(information['SSL'] == 'No'):
        suggestions['notice'].append('No SSL detected!')

    # varning spf 
    if('spf' not in information['TXT'].lower()):
        suggestions['varning'].append('No SPF record!')
    
    # php
    if('5.' in information['PHP']):
        suggestions['varning'].append('Low PHP version!')
    if(information['PHP']==''):
        suggestions['notice'].append('PHP version not detected!')

    # varning mx ip dont match 
    if(information['IP'] != information['MXIP']):
        if(information['MXIP']==''):
            suggestions['varning'].append('MX host lookup failed!')
        else:
            if('oderland' in information['MXH'].lower() and 'oderland' in information['HOST'].lower()):
                pass
            else:
                suggestions['notice'].append('External mail detected!')

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
    information['SNI'] = domain_punycode

    # init ip list for domain
    ips = []

    # get whois from domain name
    try:
        whois = pythonwhois.get_whois(domain, True)
    except UnicodeDecodeError:
        whois = False
        information['ERR1'] = 'Python whois UnicodeDecodeError (Domain)'

    # get Wordpress admin login status code
    try:
        r = requests.get('http://{}/wp-admin'.format(domain))
        if(r.status_code == 200):
            information['WP'] = True
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        information['WP'] = False

    # get main site status code
    try:
        html = urllib.request.urlopen('http://{}'.format(domain))
        site = lxml.html.parse(html)
        information['TITLE'] = site.find(".//title").text
    except urllib.error.HTTPError:
        information['TITLE'] = ''

    # get SSL cert
    try:
        cert = requests.get('https://{}'.format(domain), verify=True)
        information['SSL'] = 'Yes'
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        information['SSL'] = 'No'
    
    try:
        site = requests.get('http://{}'.format(domain))
        information['SRV'] = site.headers['server']
    except:
        information['SRV'] = ''

    # get php version
    try:
        result = requests.get('http://{}'.format(domain))
        try:
            php = result.headers['X-Powered-By']
        except KeyError:
            php = ''
    except:
        php = ''
    information['PHP'] = php

    # get expiry date
    try:
        information['EXP'] = whois['expiration_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        information['EXP'] = ''

    # get modified
    try:
        information['MOD'] = whois['updated_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        information['MOD'] = ''

    # get status
    try:
        status = ','.join(whois['status'])
    except (KeyError, TypeError):
        status = ''
    information['STAT'] = status

    try:
        reg = ' '.join(whois['registrar'])
    except (KeyError, TypeError):
        reg = ''
    information['REG'] = reg

    try:
        ns_ = ' '.join(whois['nameservers'])
    except (KeyError, TypeError):
        ns_ = ''
    information['DNS'] = ns_

    # get ip from domain
    try:
        answers = res.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        information['IP'] = ' / '.join(ips)

        # get host from ip
        try:
            host = socket.gethostbyaddr(ips[0])[0]
        except socket.error:
            host = ''
        information['HOST'] = host

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
        information['ORG'] = org

    except dns.resolver.NXDOMAIN:
        information['ERR'] = 'ERR\tNo such domain (NXDOMAIN)'
    except dns.resolver.Timeout:
        information['ERR'] = 'ERR\tTimeout'
    except dns.exception.DNSException:
        information['ERR'] = 'ERR\tDNSException'

    mx_ = subprocess.check_output(['dig', '+noall', '+answer', 'MX', domain]).decode('unicode_escape').strip().replace('\n', '\n\t')
    if mx_:
        information['MX'] = mx_
    else:
        information['MX'] = ''

    # get mx host
    if(information['MX']):
        try:
            information['MXH'] = re.findall('([a-zA-Z0-9\-]{1,}\.[a-zA-Z0-9\-]{1,}\.[a-zA-Z0-9]{1,}\.?[a-zA-Z0-9]{0,})',information['MX'])[0]
        except IndexError:
            if('mx' in information['MX'].lower()):
                information['MXH'] = information['name']
            else:
                information['MXH'] = ''
        try:
            ips = []
            mx_answers = res.query(information['MXH'])
            for rdata in mx_answers:
                ips.append(rdata.address)
            information['MXIP'] = ips[0]
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
            information['MXIP'] = ''
            

    information['TXT'] = subprocess.check_output(['dig', '+noall', '+answer', 'TXT', domain]).decode('unicode_escape').strip().replace('\n', '\n\t')

    return information

def output_console(information, suggestions):
    """output suggestions to console"""
    for key, value in information.items():
        if value:
            if(value == True):
                value = 'Yes'
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], value))
        else:
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], UNKNOWN))
    for error_msg in suggestions['errors']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['red'], error_msg, COLOR['end']))
    for varning_msg in suggestions['varning']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['yellow'], varning_msg, COLOR['end']))
    for notice_msg in suggestions['notice']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['darkcyan'], notice_msg, COLOR['end']))
#test

if __name__ == "__main__":
    main()

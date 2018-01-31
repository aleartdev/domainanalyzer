#!/usr/bin/env python3
# coding=utf-8
"""Analyzes given domainnamne and pressents important information"""
import sys
import socket
import subprocess
import time
import urllib
#from urllib.request import urlopen
import re
import requests
import pythonwhois
import dns
from dns import resolver
import lxml.html

# This fix needs to be used on net.py in pythonwhois on your local computer
# to correctly handle non standard characters
# https://github.com/joepie91/python-whois/pull/59

# TODO: stackoverflow.com fix MXH to complete domain name
# TODO: make the script run in Docker instead
# TODO: get all external data trough threads in beginning of script
# TODO: dont check non domain first argument, exit with notice

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
    suggestions = {'error':[], 'varning':[], 'notice':[]}

    # TODO: if mx on other ip then varning on ssl problem. 

    # varning status
    if 'ok' not in information['STAT'] and 'transfer' not in information['STAT'].lower():
        suggestions['error'].append('Domain status code not OK!')

    # notice status
    if 'transfer' in information['STAT'].lower():
        suggestions['notice'].append('Domain transfer status code!')
    else:
        if 'ok' not in information['STAT'].lower():
            suggestions['error'].append('Domain status code not OK!')

    # notice ssl
    if information['SSL'] == 'No':
        if problem == 'ssl':
            suggestions['error'].append('No SSL detected!')
        else:
            suggestions['notice'].append('No SSL detected!')

    # varning spf
    if 'spf' not in information['TXT'].lower():
        if problem == 'mail':
            suggestions['error'].append('No SPF record!')
        else:
            suggestions['varning'].append('No SPF record!')


    # php
    if '5.' in information['PHP']:
        suggestions['varning'].append('Low PHP version!')
    if information['PHP'] == '':
        suggestions['notice'].append('PHP version not detected!')

    # varning mx ip dont match
    if information['MX'] and (information['IP'] != information['MXIP']):
        if information['MXIP'] == '':
            suggestions['varning'].append('MX host IP lookup failed!')
        else:
            # TODO: compare TLD of host of DNS A and DNS MX ant throw notice for diff
            if 'oderland' in information['MXH'].lower() and 'oderland' in information['HOST'].lower():
                pass
            else:
                suggestions['notice'].append('Site and mail on different IP!')

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
    #information['name'] = domain.split("@")[-1] if '@' in domain else domain

    # use only domain name for rest of the script
    domain = information['name']

    # get punycode
    try:
        domain.encode(encoding='utf-8').decode('ascii')
        domain_dig = domain
    except UnicodeDecodeError:
        domain_punycode = domain.encode("idna").decode("utf-8")
        domain_dig = domain_punycode
    else:
        domain_punycode = ''
    information['IDN'] = domain_punycode

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
        result = requests.get('http://{}/wp-admin'.format(domain))
        if result.status_code == 200:
            information['WP'] = True
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        information['WP'] = False

    # get main site status code
    try:
        html = urllib.request.urlopen('http://{}'.format(domain))
        site = lxml.html.parse(html)
        information['TITLE'] = site.find(".//title").text
    except (urllib.error.HTTPError, ConnectionResetError) as error:
        information['TITLE'] = ''
        information['SPEED'] = ''
        information['ERR3'] = 'Unable to get site {}'.format(error)

    try:
        result = page_speed('http://{}'.format(domain))
        information['TTFB'] = '{} ms'.format(result['ttfb'])
        information['TTLB'] = '{} ms'.format(result['ttlb'])
    except:
        information['TTFB'] = ''
        information['TTLB'] = ''

    # get SSL cert
    try:
        requests.get('https://{}'.format(domain), verify=True)
        information['SSL'] = 'Yes'
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        information['SSL'] = 'No'

    try:
        site = requests.get('http://{}'.format(domain))
        try:
            information['SRV'] = site.headers['server']
        except KeyError:
            information['SRV'] = ''
    except requests.exceptions.RequestException as error:
        information['SRV'] = ''

    # get php version
    try:
        result = requests.get('http://{}'.format(domain))
        try:
            php = result.headers['X-Powered-By']
            if 'php' not in php.lower():
                php = ''
        except KeyError:
            php = ''
        try:
            size = round(int(result.headers['Content-length'])/1024)
            information['SIZE'] = '{} kB'.format(size)
        except KeyError:
            information['SIZE'] = ''
    except requests.exceptions.RequestException as error:
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
        except (UnicodeDecodeError, ValueError) as error:
            whois_2 = False
            information['ERR2'] = 'Python whois DecodeError (IP) {}'.format(error)
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

    dig_mx_result = subprocess.check_output(['dig', '+noall', '+answer', 'MX', domain_dig])
    mx_ = dig_mx_result.decode('unicode_escape').strip().replace('\n', '\n\t')
    if mx_:
        information['MX'] = mx_
    else:
        information['MX'] = ''

    # get mx host
    if information['MX']:
        try:
            re_domain = r'([a-zA-Z0-9\-]{1,}\.[a-zA-Z0-9\-]{1,}\.[a-zA-Z0-9]{1,}\.?[a-zA-Z0-9]{0,})'
            information['MXH'] = re.findall(re_domain, information['MX'])[0]
        except IndexError:
            if 'mx' in information['MX'].lower():
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

        if information['MXIP']:
            # get org name from MXIP
            try:
                whois_3 = pythonwhois.get_whois(information['MXIP'], True)

            except (UnicodeDecodeError, ValueError) as error:
                whois_3 = False
                information['ERR3'] = 'Python whois DecodeError (MXIP) {}'.format(error)
            try:
                mxorg = whois_3['contacts']['registrant']['name']
            except (KeyError, TypeError):
                try:
                    mxorg = whois_3['emails'][0]
                except (KeyError, TypeError):
                    mxorg = ''
            information['MXORG'] = mxorg
        else:
            information['MXORG'] = ''



    # check host of MXIP
        try:
            information['MXH2'] = socket.gethostbyaddr(information['MXIP'])[0]
        except socket.error:
            information['MXH2'] = ''
    else:
        information['MXH2'] = ''
        information['MXORG'] = ''


    # dig +noall +answer TXT domain
    dig_txt_result = subprocess.check_output(['dig', '+noall', '+answer', 'TXT', domain_dig])
    information['TXT'] = dig_txt_result.decode('unicode_escape').strip().replace('\n', '\n\t')

    return information

def output_console(information, suggestions):
    """output suggestions to console"""
    for key, value in information.items():
        if value:
            if value is True:
                value = 'Yes'
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], value))
        else:
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], UNKNOWN))
    for error_msg in suggestions['error']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['red'], error_msg, COLOR['end']))
    for varning_msg in suggestions['varning']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['yellow'], varning_msg, COLOR['end']))
    for notice_msg in suggestions['notice']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['darkcyan'], notice_msg, COLOR['end']))

def page_speed(url):
    """get ttfb and ttlb from url"""
    opener = urllib.request.build_opener()
    request = urllib.request.Request(url)

    start = int(round(time.time() * 1000))
    resp = opener.open(request)
    # read one byte
    resp.read(1)
    ttfb = int(round(time.time() * 1000)) - start
    # read the rest
    resp.read()
    ttlb = int(round(time.time() * 1000)) - start
    return {'ttfb': ttfb, 'ttlb': ttlb}

if __name__ == "__main__":
    main()

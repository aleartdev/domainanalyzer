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
import asyncio

# This fix needs to be used on net.py in pythonwhois on your local computer
# to correctly handle non standard characters
# https://github.com/joepie91/python-whois/pull/59

# TODO: stackoverflow.com fix MXH to complete domain name
# TODO: make the script run in Docker instead
# TODO: get all external data trough threads in beginning of script
# TODO: dont check non domain first argument, exit with notice
# threadding branch test

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

INFORMATION = {}

@asyncio.coroutine
def get_whois(domain):
    """get whois from domain name"""
    try:
        whois = pythonwhois.get_whois(domain, True)
        return whois
    except UnicodeDecodeError:
        INFORMATION['ERR1'] = 'Python whois UnicodeDecodeError (Domain)'
        return False

@asyncio.coroutine
def get_wpadmin(domain):
    """get Wordpress admin login status code"""
    try:
        result = requests.get('http://{}/wp-admin'.format(domain))
        if result.status_code == 200:
            INFORMATION['WP'] = True
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        INFORMATION['WP'] = False

@asyncio.coroutine
def get_statuscodes(domain):
    """get main site status code"""
    try:
        html = urllib.request.urlopen('http://{}'.format(domain))
        site = lxml.html.parse(html)
        INFORMATION['TITLE'] = site.find(".//title").text
    except (urllib.error.HTTPError, ConnectionResetError) as error:
        INFORMATION['TITLE'] = ''
        INFORMATION['SPEED'] = ''
        INFORMATION['ERR3'] = 'Unable to get site {}'.format(error)

@asyncio.coroutine
def get_ssl(domain):
    """get SSL cert"""
    try:
        requests.get('https://{}'.format(domain), verify=True)
        INFORMATION['SSL'] = 'Yes'
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        INFORMATION['SSL'] = 'No'

@asyncio.coroutine
def get_srv(domain):
    """get server information """
    try:
        site = requests.get('http://{}'.format(domain))
        try:
            INFORMATION['SRV'] = site.headers['server']
        except KeyError:
            INFORMATION['SRV'] = ''
    except requests.exceptions.RequestException as error:
        INFORMATION['SRV'] = ''

@asyncio.coroutine
def get_php(domain):
    """get php version"""
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
            INFORMATION['SIZE'] = '{} kB'.format(size)
        except KeyError:
            INFORMATION['SIZE'] = ''
    except requests.exceptions.RequestException as error:
        php = ''
    INFORMATION['PHP'] = php


def main():
    """Main function"""
    domain = get_argument(1, None)
    problem = get_argument(2, None)
    get_information(domain)
    suggestions = analyze(problem)
    output_console(suggestions)

def analyze(problem):
    """Get suggestions what can be fixed"""
    suggestions = {'error':[], 'varning':[], 'notice':[]}

    # TODO: if mx on other ip then varning on ssl problem. 

    # varning status
    if 'ok' not in INFORMATION['STAT'] and 'transfer' not in INFORMATION['STAT'].lower():
        suggestions['error'].append('Domain status code not OK!')

    # notice status
    if 'transfer' in INFORMATION['STAT'].lower():
        suggestions['notice'].append('Domain transfer status code!')
    else:
        if 'ok' not in INFORMATION['STAT'].lower():
            suggestions['error'].append('Domain status code not OK!')

    # notice ssl
    if INFORMATION['SSL'] == 'No':
        if problem == 'ssl':
            suggestions['error'].append('No SSL detected!')
        else:
            suggestions['notice'].append('No SSL detected!')

    # varning spf
    if 'spf' not in INFORMATION['TXT'].lower():
        if problem == 'mail':
            suggestions['error'].append('No SPF record!')
        else:
            suggestions['varning'].append('No SPF record!')


    # php
    if '5.' in INFORMATION['PHP']:
        suggestions['varning'].append('Low PHP version!')
    if INFORMATION['PHP'] == '':
        suggestions['notice'].append('PHP version not detected!')

    # varning mx ip dont match
    if INFORMATION['MX'] and (INFORMATION['IP'] != INFORMATION['MXIP']):
        if INFORMATION['MXIP'] == '':
            suggestions['varning'].append('MX host IP lookup failed!')
        else:
            # TODO: compare TLD of host of DNS A and DNS MX ant throw notice for diff
            if 'oderland' in INFORMATION['MXH'].lower() and 'oderland' in INFORMATION['HOST'].lower():
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
    INFORMATION['name'] = domain.split("//")[-1].split("/")[0] if '//' in domain else domain
    #INFORMATION['name'] = domain.split("@")[-1] if '@' in domain else domain

    # use only domain name for rest of the script
    domain = INFORMATION['name']

    # get punycode
    try:
        domain.encode(encoding='utf-8').decode('ascii')
        domain_dig = domain
    except UnicodeDecodeError:
        domain_punycode = domain.encode("idna").decode("utf-8")
        domain_dig = domain_punycode
    else:
        domain_punycode = ''
    INFORMATION['IDN'] = domain_punycode

    # init ip list for domain
    ips = []

    loop = asyncio.get_event_loop()
    # get whois from domain name
    tasks = get_whois(domain), get_wpadmin(domain), get_statuscodes(domain), page_speed(domain), get_ssl(domain), get_srv(domain), get_php(domain)
    
    whois, wp_result, statuscodes, speed, ssl, srv, php = loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()

    # get expiry date
    try:
        INFORMATION['EXP'] = whois['expiration_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['EXP'] = ''

    # get modified
    try:
        INFORMATION['MOD'] = whois['updated_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['MOD'] = ''

    # get status
    try:
        status = ','.join(whois['status'])
    except (KeyError, TypeError):
        status = ''
    INFORMATION['STAT'] = status

    try:
        reg = ' '.join(whois['registrar'])
    except (KeyError, TypeError):
        reg = ''
    INFORMATION['REG'] = reg

    try:
        ns_ = ' '.join(whois['nameservers'])
    except (KeyError, TypeError):
        ns_ = ''
    INFORMATION['DNS'] = ns_

    # get ip from domain
    try:
        answers = res.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        INFORMATION['IP'] = ' / '.join(ips)

        # get host from ip
        try:
            host = socket.gethostbyaddr(ips[0])[0]
        except socket.error:
            host = ''
        INFORMATION['HOST'] = host

        # get name from ip
        try:
            whois_2 = pythonwhois.get_whois(ips[0], True)
        except (UnicodeDecodeError, ValueError) as error:
            whois_2 = False
            INFORMATION['ERR2'] = 'Python whois DecodeError (IP) {}'.format(error)
        try:
            org = whois_2['contacts']['registrant']['name']
        except (KeyError, TypeError):
            try:
                org = whois_2['emails'][0]
            except (KeyError, TypeError):
                org = ''
        INFORMATION['ORG'] = org

    except dns.resolver.NXDOMAIN:
        INFORMATION['ERR'] = 'ERR\tNo such domain (NXDOMAIN)'
    except dns.resolver.Timeout:
        INFORMATION['ERR'] = 'ERR\tTimeout'
    except dns.exception.DNSException:
        INFORMATION['ERR'] = 'ERR\tDNSException'

    dig_mx_result = subprocess.check_output(['dig', '+noall', '+answer', 'MX', domain])
    mx_ = dig_mx_result.decode('unicode_escape').strip().replace('\n', '\n\t')
    if mx_:
        INFORMATION['MX'] = mx_
    else:
        INFORMATION['MX'] = ''

    # get mx host
    if INFORMATION['MX']:
        try:
            re_domain = r'([a-zA-Z0-9\-]{1,}\.[a-zA-Z0-9\-]{1,}\.[a-zA-Z0-9]{1,}\.?[a-zA-Z0-9]{0,})'
            INFORMATION['MXH'] = re.findall(re_domain, INFORMATION['MX'])[0]
        except IndexError:
            if 'mx' in INFORMATION['MX'].lower():
                INFORMATION['MXH'] = INFORMATION['name']
            else:
                INFORMATION['MXH'] = ''
        try:
            ips = []
            mx_answers = res.query(INFORMATION['MXH'])
            for rdata in mx_answers:
                ips.append(rdata.address)
            INFORMATION['MXIP'] = ips[0]
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
            INFORMATION['MXIP'] = ''

        if INFORMATION['MXIP']:
            # get org name from MXIP
            try:
                whois_3 = pythonwhois.get_whois(INFORMATION['MXIP'], True)

            except (UnicodeDecodeError, ValueError) as error:
                whois_3 = False
                INFORMATION['ERR3'] = 'Python whois DecodeError (MXIP) {}'.format(error)
            try:
                mxorg = whois_3['contacts']['registrant']['name']
            except (KeyError, TypeError):
                try:
                    mxorg = whois_3['emails'][0]
                except (KeyError, TypeError):
                    mxorg = ''
            INFORMATION['MXORG'] = mxorg
        else:
            INFORMATION['MXORG'] = ''



    # check host of MXIP
        try:
            INFORMATION['MXH2'] = socket.gethostbyaddr(INFORMATION['MXIP'])[0]
        except socket.error:
            INFORMATION['MXH2'] = ''
    else:
        INFORMATION['MXH2'] = ''
        INFORMATION['MXORG'] = ''


    # dig +noall +answer TXT domain
    dig_txt_result = subprocess.check_output(['dig', '+noall', '+answer', 'TXT', domain_dig])
    INFORMATION['TXT'] = dig_txt_result.decode('unicode_escape').strip().replace('\n', '\n\t')

def output_console(suggestions):
    """output suggestions to console"""
    for key, value in INFORMATION.items():
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

@asyncio.coroutine
def page_speed(domain):
    """get ttfb and ttlb from url"""
    url = 'http://{}'.format(domain)
    opener = urllib.request.build_opener()
    request = urllib.request.Request(url)

    start = int(round(time.time() * 1000))
    resp = opener.open(request)
    # read one byte
    resp.read(1)
    INFORMATION['TTFB_MS'] = int(round(time.time() * 1000)) - start
    # read the rest
    resp.read()
    INFORMATION['TTLB_MS'] = int(round(time.time() * 1000)) - start

if __name__ == "__main__":
    main()

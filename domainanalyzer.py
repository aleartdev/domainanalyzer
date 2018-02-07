#!/usr/bin/env python3
# coding=utf-8
"""Analyzes given domainnamne and pressents important information"""
import sys
import socket
import subprocess
import time
import urllib
import re
import requests
import pythonwhois
import dns
from dns import resolver
import lxml.html
from threading import Thread
import threading
from collections import OrderedDict

# This fix needs to be used on net.py in pythonwhois on your local computer
# to correctly handle non standard characters
# https://github.com/joepie91/python-whois/pull/59

# TODO: stackoverflow.com fix MXH to complete domain name
# TODO: make the script run in Docker instead
# TODO: dont check non domain name first argument, exit with notice
# TODO: dont fail on non existing domain
# TODO: threading on all heavy lifting. Get domain IP first before heavy lift. Start all at same time and add more on certiain return?
# TODO: cloud flare failurllib.error.HTTPError: HTTP Error 403: Forbidden http://104.18.54.15/

# SETTINGS
RESOVING_NAMESERVER = '8.8.8.8'
DEBUG = False
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

# GLOBALS to write to from threads
WHOIS = False
INFORMATION = {}

def main():
    """Main function"""
    
    domain = get_argument(1, None)
    problem = get_argument(2, None)
    get_information(domain)
    suggestions = analyze(problem)
    output_console(suggestions)

def get_argument(index, return_except):
    """get argument at index or returns return_except"""
    try:
        return sys.argv[index]
    except IndexError:
        return return_except

def get_information(domain):
    """get information about the domain"""

    # get only domain name
    INFORMATION['NAME'] = domain.split("//")[-1].split("/")[0] if '//' in domain else domain

    # use only domain name for rest of the script
    domain = INFORMATION['NAME']

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


    # 88888888888 888    888 8888888b.  8888888888        d8888 8888888b. 8888888 888b    888  .d8888b.  
    #     888     888    888 888   Y88b 888              d88888 888  "Y88b  888   8888b   888 d88P  Y88b 
    #     888     888    888 888    888 888             d88P888 888    888  888   88888b  888 888    888 
    #     888     8888888888 888   d88P 8888888        d88P 888 888    888  888   888Y88b 888 888        
    #     888     888    888 8888888P"  888           d88P  888 888    888  888   888 Y88b888 888  88888 
    #     888     888    888 888 T88b   888          d88P   888 888    888  888   888  Y88888 888    888 
    #     888     888    888 888  T88b  888         d8888888888 888  .d88P  888   888   Y8888 Y88b  d88P 
    #     888     888    888 888   T88b 8888888888 d88P     888 8888888P" 8888888 888    Y888  "Y8888P88

    # Split work into threads
    event_ip = threading.Event()
    functions = get_whois, get_wpadmin, get_statuscodes, page_speed, get_ssl, get_srv, get_php, get_ip, get_host, get_mxorg
    threads_list = list()
    for function in functions:
        threads_list.append(Thread(name=function, target=function, args=(domain, event_ip)))
    
    for thread in threads_list:
        thread.start()

    for thread in threads_list:
        thread.join()

    # get expiry date
    try:
        INFORMATION['EXP'] = WHOIS['expiration_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['EXP'] = ''
    
    # get expiry date
    try:
        INFORMATION['CRE'] = WHOIS['creation_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['CRE'] = ''

    # get modified
    try:
        INFORMATION['MOD'] = WHOIS['updated_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['MOD'] = ''

    # get status
    try:
        status = ','.join(WHOIS['status'])
    except (KeyError, TypeError):
        status = ''
    INFORMATION['STAT'] = status

    try:
        reg = ' '.join(WHOIS['registrar'])
    except (KeyError, TypeError):
        reg = ''
    INFORMATION['REG'] = reg

    try:
        ns_ = ' '.join(WHOIS['nameservers'])
    except (KeyError, TypeError):
        ns_ = ''
    INFORMATION['DNS'] = ns_


    # get ip from domain
    res = resolver.Resolver()
    res.nameservers = [RESOVING_NAMESERVER]
    ips = []

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
                INFORMATION['MXH'] = INFORMATION['NAME']
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



def analyze(problem):
    """Get suggestions what can be fixed"""
    suggestions = {'error':[], 'varning':[], 'notice':[]}

    # TODO: if mx on other ip then varning on ssl problem. 

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

def output_console(suggestions):
    """output suggestions to console"""
    global INFORMATION
    INFORMATION = OrderedDict(sorted(INFORMATION.items()))
    for key, value in INFORMATION.items():
        if value:
            if value is True:
                value = 'Yes'
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], value))
        else:
            print('{}{}{}\t{}'.format(COLOR['bold'], key, COLOR['end'], ''))
    for error_msg in suggestions['error']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['red'], error_msg, COLOR['end']))
    for varning_msg in suggestions['varning']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['yellow'], varning_msg, COLOR['end']))
    for notice_msg in suggestions['notice']:
        print('{}{}{}{}'.format(COLOR['bold'], COLOR['darkcyan'], notice_msg, COLOR['end']))

def get_host(domain, event_ip):
    # get host from ip when ip is avalible
    event_ip.wait()
    if DEBUG:
        print('get_host start')
    global INFORMATION
    try:
        host = socket.gethostbyaddr(INFORMATION['IP'])[0]
    except socket.error:
        host = ''
    INFORMATION['HOST'] = host
    if DEBUG:
        print('get_host stop')

def get_mxorg(domain, event_ip):
    # get Org name from mx ip when ip is avalible
    event_ip.wait()
    if DEBUG:
        print('get_mxorg start')
    global INFORMATION
    
    try:
        try:
            whois_2 = pythonwhois.get_whois(INFORMATION['IP'], True)
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
        if DEBUG:
            print('get_mxorg stop')

    except dns.resolver.NXDOMAIN:
        INFORMATION['ERR'] = 'ERR\tNo such domain (NXDOMAIN)'
    except dns.resolver.Timeout:
        INFORMATION['ERR'] = 'ERR\tTimeout'
    except dns.exception.DNSException:
        INFORMATION['ERR'] = 'ERR\tDNSException'
        
def get_whois(domain, event_ip):
    """get whois from domain name"""
    global WHOIS
    if DEBUG:
        print('get_whois start {}'.format(domain))
    try:
        WHOIS = pythonwhois.get_whois(domain, True)
        if DEBUG:
            print('get_whois stop (success)')
    except UnicodeDecodeError:
        INFORMATION['ERR1'] = 'Python whois UnicodeDecodeError (Domain)'
        WHOIS = False
        if DEBUG:
            print('get_whois stop (with error)')

def get_ip(domain, event_ip):
    """get whois from domain name"""
    if DEBUG:
        print('get_ip start {}'.format(domain))
    # create resolver object
    res = resolver.Resolver()
    res.nameservers = [RESOVING_NAMESERVER]
    ips = []
    try:
        answers = res.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        INFORMATION['IP'] = ips[0]
    except dns.resolver.NXDOMAIN:
        INFORMATION['ERR'] = 'ERR\tNo such domain (NXDOMAIN)'
    except dns.resolver.Timeout:
        INFORMATION['ERR'] = 'ERR\tTimeout'
    except dns.exception.DNSException:
        INFORMATION['ERR'] = 'ERR\tDNSException'
    if DEBUG:
        print('get_ip stop')
    event_ip.set()

def get_wpadmin(domain, event_ip):
    """get Wordpress admin login status code"""
    if DEBUG:
        print('get_wpadmin start')
    try:
        result = requests.get('http://{}/wp-admin'.format(domain))
        if result.status_code == 200:
            INFORMATION['WP'] = True
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        INFORMATION['WP'] = False
    if DEBUG:
        print('get_wpadmin stop')

def get_statuscodes(domain, event_ip):
    """get main site status code"""
    if DEBUG:
        print('get_statuscodes start')
    try:
        html = urllib.request.urlopen('http://{}'.format(domain))
        site = lxml.html.parse(html)
        try:
            INFORMATION['TITLE'] = site.find(".//title").text
        except AttributeError:
            INFORMATION['TITLE'] = 'No title tag found'
    except (urllib.error.HTTPError, ConnectionResetError) as error:
        INFORMATION['TITLE'] = ''
        INFORMATION['SPEED'] = ''
        INFORMATION['ERR3'] = 'xUnable to get site {}'.format(error)
    if DEBUG:
        print('get_statuscodes stop')

def get_ssl(domain, event_ip):
    """get SSL cert"""
    if DEBUG:
        print('get_ssl start')
    try:
        requests.get('https://{}'.format(domain), verify=True)
        INFORMATION['SSL'] = 'Yes'
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        INFORMATION['SSL'] = 'No'
    if DEBUG:
        print('get_ssl stop')

def get_srv(domain, event_ip):
    """get server information """
    if DEBUG:
        print('get_srv start')
    try:
        site = requests.get('http://{}'.format(domain))
        try:
            INFORMATION['SRV'] = site.headers['server']
        except KeyError:
            INFORMATION['SRV'] = ''
    except requests.exceptions.RequestException:
        INFORMATION['SRV'] = ''
    if DEBUG:
        print('get_srv stop')

def get_php(domain, event_ip):
    """get php version"""
    if DEBUG:
        print('get_php start')
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
    except requests.exceptions.RequestException:
        php = ''
    INFORMATION['PHP'] = php
    if DEBUG:
        print('get_php stop')

def page_speed(domain, event_ip):
    """get ttfb and ttlb from url"""
    try:
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
    except urllib.error.HTTPError:
        pass

if __name__ == "__main__":
    main()

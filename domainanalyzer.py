#!/usr/bin/env python3
# coding=utf-8
"""Get information and discover problems with a domain name"""
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

# TODO make the script run in Docker instead
# TODO dont check non domain name first argument, exit with notice
# TODO dont fail on non existing domain
# TODO <48 hour DNS change warning.
# TODO Unit test
# TODO Static type checking mypy

# SETTINGS
RESOVING_NAMESERVER = '8.8.8.8'
RES = resolver.Resolver()
RES.nameservers = [RESOVING_NAMESERVER]
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
    """Main"""
    domain = get_argument(1, None)
    problem = get_argument(2, None)
    get_information(domain)
    suggestions = analyze(problem)
    output_console(suggestions)

def get_argument(index, return_except):
    """get arguments"""
    try:
        return sys.argv[index]
    except IndexError:
        return return_except

def get_information(search):
    """get domain information"""

    INFORMATION['SEARCH'] = search

    # get only domain name
    INFORMATION['DN'] = search.split("//")[-1].split("/")[0] if '//' in search else search

    # use only domain name for rest of the script
    domain = INFORMATION['DN']

    # get punycode
    try:
        domain.encode(encoding='utf-8').decode('ascii')
    except UnicodeDecodeError:
        domain_punycode = domain.encode("idna").decode("utf-8")
    else:
        domain_punycode = ''
    INFORMATION['IDN'] = domain_punycode

    # Split work into threads
    event_ip = threading.Event()
    functions = get_whois, get_wpadmin, get_statuscodes, page_speed, get_ssl, get_srv, get_php, get_ip, get_host, get_mxorg, get_mx, get_txt
    threads_list = list()
    for function in functions:
        threads_list.append(Thread(name=function, target=function, args=(domain, event_ip)))
    
    for thread in threads_list:
        thread.start()

    for thread in threads_list:
        thread.join()

def analyze(problem):
    """Analyze problems with domain"""
    suggestions = {'error':[], 'warning':[], 'notice':[]}

    # notice slow site
    if INFORMATION['TTLB_MS']:
        if INFORMATION['TTLB_MS']>1000:
            if '5.' in INFORMATION['PHP']:
                suggestions['warning'].append('Slow site (Low PHP version detected)')
            elif INFORMATION['PHP']:
                suggestions['notice'].append('Slow site (Not PHP version related)')
            else:
                suggestions['notice'].append('Slow site (PHP version not detected)')

    if 'cloudflare' in INFORMATION['SRV']:
        suggestions['notice'].append('Cloudflare!')

    # warning no host 
    if not INFORMATION['HOST'] and INFORMATION['IP']:
        suggestions['warning'].append('No host name for A-pointer, possible on VPS or dedicated IP!')

    # no ip 
    if not INFORMATION['IP']:
        suggestions['error'].append('No IP (No A-pointer)')

    # status
    if 'transfer' in INFORMATION['STAT'].lower():
        suggestions['notice'].append('Status code include "TRANSFER"')
    else:
        if 'ok' not in INFORMATION['STAT'].lower():
            suggestions['error'].append('Status code not "OK"')

    # ssl
    if INFORMATION['SSL'] == 'No':
        if problem == 'ssl':
            suggestions['error'].append('No SSL detected!')
        else:
            suggestions['notice'].append('No SSL detected!')

    # spf
    if 'spf' not in INFORMATION['TXT'].lower():
        if problem == 'mail':
            suggestions['error'].append('No SPF record!')
        else:
            suggestions['warning'].append('No SPF record!')


    if INFORMATION['HOSTDN'] != INFORMATION['MXHDN']:
        suggestions['notice'].append('Site and mail hosts on different domains!')

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
        print('Error! {}{}{}{}'.format(COLOR['bold'], COLOR['red'], error_msg, COLOR['end']))
    for warning_msg in suggestions['warning']:
        print('Warning! {}{}{}{}'.format(COLOR['bold'], COLOR['yellow'], warning_msg, COLOR['end']))
    for notice_msg in suggestions['notice']:
        print('Notice! {}{}{}{}'.format(COLOR['bold'], COLOR['darkcyan'], notice_msg, COLOR['end']))

def get_host(domain, event_ip):
    # get host from ip when ip is avalible
    event_ip.wait()
    if DEBUG:
        print('get_host start')
    global INFORMATION
    try:
        INFORMATION['HOST'] = socket.gethostbyaddr(INFORMATION['IP'])[0]
        INFORMATION['HOSTDN'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', INFORMATION['HOST'])[0] 
    except socket.error:
        INFORMATION['HOST'] = ''
    if DEBUG:
        print('get_host stop')

def get_txt(domain, event_ip):
    # get dns mx pointers for domain
    if DEBUG:
        print('get_txt start')
    global INFORMATION
    try:
        #INFORMATION['TXT'] = dig_txt_result.decode('unicode_escape').strip().replace('\n', '\n\t')
        # get txt from resolver for domain then make list and concat to string with newline
        if INFORMATION['IDN']:
            domain_dig = INFORMATION['IDN']
        else:
            domain_dig = domain
        INFORMATION['TXT'] = '\n\t'.join([txt.to_text() for txt in dns.resolver.query(domain_dig, 'TXT')])
    except (socket.error, dns.resolver.NoAnswer):
        INFORMATION['TXT'] = ''
    if DEBUG:
        print('get_txt stop')

def get_mx(domain, event_ip):
    # get dns mx pointers for domain
    if DEBUG:
        print('get_mx start')
    global INFORMATION
    try:
        # get mx from resolver for domain then make list and concat to string with newline
        INFORMATION['MX'] = '\n\t'.join([mx.to_text() for mx in dns.resolver.query(domain, 'MX')])
        # get second word that ends with a dot excluding that dot
        INFORMATION['MXH'] = re.findall(r'.* (.*).', INFORMATION['MX'])[0]
        INFORMATION['MXHDN'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', INFORMATION['MXH'])[0] 
    except (socket.error, dns.resolver.NoAnswer):
        INFORMATION['MX'] = ''
        INFORMATION['MXH'] = ''
        INFORMATION['MXHDN'] = ''
    if DEBUG:
        print('get_mx stop')
    global RES
    if INFORMATION['MXH']:
        try:
            INFORMATION['MXIP'] = RES.query(INFORMATION['MXH'])[0].address
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
            INFORMATION['MXIP'] = ''
    else:
        INFORMATION['MXIP'] = '' 
    
    if INFORMATION['MXIP']:
        # get org name from MXIP
        # move to thread waiting for MXIP if MXH exists.
        try:
            whois_3 = pythonwhois.get_whois(INFORMATION['MXIP'], True)

        except (UnicodeDecodeError, ValueError) as error:
            whois_3 = False
        try:
            mxorg = whois_3['contacts']['registrant']['name']
        except (KeyError, TypeError):
            try:
                mxorg = whois_3['emails'][0]
            except (KeyError, TypeError):
                mxorg = ''
        INFORMATION['MXORG'] = mxorg
        try:
            INFORMATION['MXHR'] = socket.gethostbyaddr(INFORMATION['MXIP'])[0]
        except socket.error:
            INFORMATION['MXHR'] = ''
    else:
        INFORMATION['MXORG'] = ''
        INFORMATION['MXHR'] = ''
        INFORMATION['MXORG'] = ''
        
def get_mxorg(domain, event_ip):
    # get Org name from mx ip when ip is avalible
    event_ip.wait()
    if DEBUG:
        print('get_mxorg start')
    global INFORMATION
    
    try:
        try:
            whois_2 = pythonwhois.get_whois(INFORMATION['IP'], True)
        except (UnicodeDecodeError, ValueError, pythonwhois.shared.WhoisException):
            whois_2 = False
        
        try:
            org = whois_2['contacts']['registrant']['name']
        except (KeyError, TypeError):
            try:
                org = whois_2['emails'][0]
            except (KeyError, TypeError):
                org = ''
        INFORMATION['MXORG'] = org
        if DEBUG:
            print('get_mxorg stop')

    except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
        INFORMATION['MXORG'] = ''
        
def get_whois(domain, event_ip):
    """get whois from domain name"""
    global INFORMATION
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

    # get registrar
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

    # Would like Tech contact and such but pwhois seems to get much less thatn whois

def get_ip(domain, event_ip):
    """get whois from domain name"""
    if DEBUG:
        print('get_ip start {}'.format(domain))
    # create resolver object
    global RES
    ips = []
    try:
        answers = RES.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        INFORMATION['IP'] = ips[0]
    except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
        INFORMATION['IP'] = ''
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
        except (AttributeError, AssertionError):
            INFORMATION['TITLE'] = ''

    except (urllib.error.HTTPError, ConnectionResetError, urllib.error.URLError) as error:
        INFORMATION['TITLE'] = ''
        INFORMATION['SPEED'] = ''
        INFORMATION['ERR3'] = 'Unable to get site {}'.format(error)
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
    except (urllib.error.HTTPError, urllib.error.URLError):
        INFORMATION['TTFB_MS'] = ''
        INFORMATION['TTLB_MS'] = ''

if __name__ == "__main__":
    main()

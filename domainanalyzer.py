#!/usr/bin/env python3
"""Get information and discover problems with a domain name."""
# coding=utf-8
import sys
import socket
import time
from datetime import datetime
import urllib
import re
import requests
import pythonwhois
import dns
from dns import resolver
import lxml.html
from threading import Thread
import threading
import http.client
import logging

# If you want pwhois to handle non standard characters in result
# you need to implement this fix on net.py in pythonwhois
# https://github.com/joepie91/python-whois/pull/59

# TODO Docker
# TODO unittest https://docs.python.org/3/library/unittest.html
# TODO Static type checking mypy http://mypy-lang.org/examples.html
# TODO import logging and

# SETTINGS
RES = resolver.Resolver()
RES.nameservers = ['8.8.8.8']
DEBUG = False

# GLOBALS to write to from threads
INFORMATION = {}


def main():
    """Main."""
    if len(sys.argv) is 1:
        sys.argv.append(input('Enter a domain name to analyze: '))
    domain = get_argument(1, None)
    problem = get_argument(2, None)

    get_information(domain)
    suggestions = analyze(problem)
    output_console(suggestions)


def get_argument(index, return_except):
    """Get arguments."""
    try:
        return sys.argv[index]
    except IndexError:
        return return_except


def parse_search(search: str) -> str:
    """So the search can be converted to a domain."""
    return search.split("//")[-1].split("/")[0] if '//' in search else search


def get_information(search):
    """Get domain information."""
    INFORMATION['SEARCH'] = search

    INFORMATION['DOMAIN NAME'] = parse_search(search)

    # use only domain name for rest of the script
    domain = INFORMATION['DOMAIN NAME']

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
    functions = [get_whois, get_wpadmin, get_statuscodes, page_speed, get_ssl,
                 get_srv, get_php, get_ip, get_host, get_mx, get_txt]
    threads_list = list()
    for function in functions:
        threads_list.append(Thread(name=function, target=function,
                            args=(domain, event_ip)))

    for thread in threads_list:
        thread.start()

    for thread in threads_list:
        thread.join()


def analyze(problem):
    """Analyze problems with domain."""
    suggestions = {'error': [], 'warning': [], 'notice': []}

    # TODO warning: <48 hour DNS change, and expire in less than one month
    if INFORMATION['TIME MODIFIED']:
        if INFORMATION['TIME MOD DELTA'] < 2:
            suggestions['warning'].append('DNS changed last 48 hours!')
        elif INFORMATION['TIME MOD DELTA'] < 7:
            if problem == 'ssl':
                suggestions['warning'].append('DNS changed last 7 days!')
            else:
                suggestions['notice'].append('DNS changed last 7 days!')

    # notice slow site
    if INFORMATION['TTLB']:
        if INFORMATION['TTLB'] > 1000:
            if '5.' in INFORMATION['PHP']:
                suggestions['warning'].append('Slow site (Low PHP version)')
            elif INFORMATION['PHP']:
                suggestions['notice'].append('Slow site (Not PHP version)')
            else:
                suggestions['notice'].append('Slow site (PHP version unknown)')

    if 'cloudflare' in INFORMATION['SERVER']:
        suggestions['notice'].append('Cloudflare!')

    # warning no host
    if not INFORMATION['HOST'] and INFORMATION['IP']:
        suggestions['notice'].append('No host found. (VPS or dedicated IP?')

    # no ip
    if not INFORMATION['IP']:
        suggestions['error'].append('No IP (No A-pointer)')

    # status
    if 'ok' not in INFORMATION['STATUS'].lower():
        suggestions['warning'].append('Status code not "OK": {}'.format(INFORMATION['STATUS']))

    # ssl
    if INFORMATION['SSL'] == 'No':
        if problem == 'ssl':
            suggestions['error'].append('No SSL detected!')
        else:
            suggestions['notice'].append('No SSL detected!')

    # spf
    if 'spf' not in INFORMATION['TXT'].lower():
        # no SPF record
        if problem == 'mail':
            suggestions['error'].append('No SPF record!')
        else:
            suggestions['warning'].append('No SPF record!')
    else:
        # SPF record exits
        if not any(host_ in INFORMATION['TXT'] for host_ in [INFORMATION['MX DOMAIN NAME'], host_domain(INFORMATION['MX ORGANIZATION']), host_domain(INFORMATION['MXHR'])]):
            suggestions['warning'].append('Mail host not in SPF!')
        if INFORMATION['IP'] not in INFORMATION['TXT']:
            if INFORMATION['IP'] is INFORMATION['MXIP']:
                # warning: ip not in spf and site and mail on same server
                suggestions['warning'].append('IP not in SPF!')
            else:
                # notice: ip not in spf and site and mail on different server
                suggestions['notice'].append('IP not in SPF!')

    # mail
    if INFORMATION['DOMAIN NAME HOST'] not in INFORMATION['MXHR'] and INFORMATION['MX DOMAIN NAME']:
        suggestions['notice'].append('External mail hosted at {} ({})!'.format(INFORMATION['MX DOMAIN NAME'], INFORMATION['MX ORGANIZATION']))

    return suggestions


def host_domain(host):
    """Return domain from host."""
    return '.'.join(host.split('.')[-2:])


def output_console(suggestions):
    """Output suggestions to console."""
    color = {
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
    for key, value in sorted(INFORMATION.items()):
        if value:
            if value is True:
                # make True visible in output
                value = 'Yes'
            print('{}{}{}{}'.format(color['bold'], "{:<17}".format(key),
                                    color['end'], value))
        else:
            print('{}{}{}{}'.format(color['bold'],
                                    key, color['end'], ''))
    for error_msg in suggestions['error']:
        print('Error! {}{}{}{}'.format(color['bold'], color['red'],
                                       error_msg, color['end']))
    for warning_msg in suggestions['warning']:
        print('Warning! {}{}{}{}'.format(color['bold'], color['yellow'],
                                         warning_msg, color['end']))
    for notice_msg in suggestions['notice']:
        print('Notice! {}{}{}{}'.format(color['bold'], color['darkcyan'],
                                        notice_msg, color['end']))


def get_host(domain, event_ip):
    """Get host from domain name."""
    # we must wait for ip to be avalible from other thread
    event_ip.wait()
    if DEBUG:
        print('get_host start')
    global INFORMATION
    try:
        INFORMATION['HOST'] = socket.gethostbyaddr(INFORMATION['IP'])[0]
        INFORMATION['DOMAIN NAME HOST'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)',
                                                     INFORMATION['HOST'])[0]
    except socket.error:
        INFORMATION['HOST'] = ''
        INFORMATION['DOMAIN NAME HOST'] = ''

    if DEBUG:
        print('get_host stop')


def get_txt(domain, event_ip):
    """Get TXT from domain name."""
    if DEBUG:
        print('get_txt start')
    global INFORMATION
    try:
        if INFORMATION['IDN']:
            domain_dig = INFORMATION['IDN']
        else:
            domain_dig = domain
        INFORMATION['TXT'] = '\n\t\t '.join([txt.to_text() for txt in dns.resolver.query(domain_dig, 'TXT')])
    except (socket.error, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        INFORMATION['TXT'] = ''
    if DEBUG:
        print('get_txt stop')


def get_mx(domain, event_ip):
    """Get MX from domain name."""
    if DEBUG:
        print('get_mx start')
    global INFORMATION
    try:
        # get mx from resolver and make list and make string
        INFORMATION['MX'] = '\n\t\t '.join([mx.to_text() for mx in dns.resolver.query(domain, 'MX')])
        # get second word that ends with a dot excluding that dot
        INFORMATION['MX HOST'] = re.findall(r'.* (.*).', INFORMATION['MX'])[0]
        INFORMATION['MX DOMAIN NAME'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', INFORMATION['MX HOST'])[0]
    except (socket.error, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        INFORMATION['MX'] = ''
        INFORMATION['MX HOST'] = ''
        INFORMATION['MX DOMAIN NAME'] = ''
    if DEBUG:
        print('get_mx stop')
    global RES
    if INFORMATION['MX HOST']:
        try:
            INFORMATION['MXIP'] = RES.query(INFORMATION['MX HOST'])[0].address
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout,
                dns.exception.DNSException):
            INFORMATION['MXIP'] = ''
    else:
        INFORMATION['MXIP'] = ''

    if INFORMATION['MXIP']:
        # get org name from MXIP
        try:
            _whois = pythonwhois.get_whois(INFORMATION['MXIP'], True)
            INFORMATION['MX ORGANIZATION'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', _whois['emails'][0])[0]
        except (UnicodeDecodeError, ValueError):
            INFORMATION['MX ORGANIZATION'] = ''
        try:
            INFORMATION['MXHR'] = socket.gethostbyaddr(INFORMATION['MXIP'])[0]
        except socket.error:
            INFORMATION['MXHR'] = ''
    else:
        INFORMATION['MX ORGANIZATION'] = ''
        INFORMATION['MXHR'] = ''
        INFORMATION['MX ORGANIZATION'] = ''


def get_mxorg(domain, event_ip):
    """Get organization from MX IP."""
    # we must wait for ip to be avalible from other thread
    event_ip.wait()
    if DEBUG:
        print('get_mxorg start')
    global INFORMATION
    try:
        try:
            whois_2 = pythonwhois.get_whois(INFORMATION['IP'], True)
        except (UnicodeDecodeError, ValueError,
                pythonwhois.shared.WhoisException):
            whois_2 = False

        try:
            org = whois_2['contacts']['registrant']['name']
        except (KeyError, TypeError):
            try:
                org = whois_2['emails'][0]
            except (KeyError, TypeError):
                org = ''
        INFORMATION['MX ORGANIZATION'] = org
        if DEBUG:
            print('get_mxorg stop')

    except (dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        INFORMATION['MX ORGANIZATION'] = ''


def get_whois(domain, event_ip):
    """Get whois from domain name."""
    global INFORMATION
    if DEBUG:
        print('get_whois start {}'.format(domain))
    if domain.count('.') > 1:
        domain = '.'.join(domain.split('.')[-2:])
    try:
        _whois = pythonwhois.get_whois(domain, True)
        if DEBUG:
            print('get_whois stop (success)')
    except UnicodeDecodeError:
        INFORMATION['error'] = 'Python whois UnicodeDecodeError'
        if DEBUG:
            print('get_whois (exception)')

    try:
        INFORMATION['TIME EXPIRE'] = _whois['expiration_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['TIME EXPIRE'] = ''

    try:
        INFORMATION['TIME CREATED'] = _whois['creation_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFORMATION['TIME CREATED'] = ''

    try:
        INFORMATION['TIME MODIFIED'] = _whois['updated_date'][0].strftime("%Y-%m-%d %H:%I:%S")
        _detla_datetime = datetime.now() - _whois['updated_date'][0]
        INFORMATION['TIME MOD DELTA'] = round((_detla_datetime.seconds / 3600 / 24) + float(_detla_datetime.days), 2)
    except (KeyError, TypeError):
        INFORMATION['TIME MODIFIED'] = ''
        INFORMATION['TIME MOD DELTA'] = ''

    try:
        INFORMATION['STATUS'] = ','.join(_whois['status'])
    except (KeyError, TypeError):
        INFORMATION['STATUS'] = ''

    try:
        INFORMATION['REGISTRAR'] = ' '.join(_whois['registrar'])
    except (KeyError, TypeError):
        INFORMATION['REGISTRAR'] = ''

    try:
        INFORMATION['DNS'] = ' '.join(_whois['nameservers'])
    except (KeyError, TypeError):
        INFORMATION['DNS'] = ''

    if DEBUG:
        print('get_whois stop')


def get_ip(domain, event_ip):
    """Get whois from domain name."""
    if DEBUG:
        print('get_ip start {}'.format(domain))
    ips = []
    try:
        answers = RES.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        INFORMATION['IP'] = ips[0]
    except dns.resolver.NXDOMAIN:
        INFORMATION['IP'] = ''
        INFORMATION['DOMAIN NAME'] = '{} (No such domain)'.format(
            INFORMATION['DOMAIN NAME'])
    except (dns.resolver.NXDOMAIN, dns.resolver.Timeout,
            dns.exception.DNSException):
        INFORMATION['IP'] = ''

    if DEBUG:
        print('get_ip stop')
    event_ip.set()


def get_wpadmin(domain, event_ip):
    """Get Wordpress admin login status code."""
    if DEBUG:
        print('get_wpadmin start')
    try:
        result = requests.get('http://{}/wp-admin'.format(domain))
        if result.status_code == 200:
            INFORMATION['WORDPRESS'] = True
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        INFORMATION['WORDPRESS'] = False
    if DEBUG:
        print('get_wpadmin stop')


def get_statuscodes(domain, event_ip):
    """Get main site status code."""
    if DEBUG:
        print('get_statuscodes start')
    try:
        html = urllib.request.urlopen('http://{}'.format(domain))
        site = lxml.html.parse(html)
        try:
            INFORMATION['TITLE'] = site.find(".//title").text
        except (AttributeError, AssertionError):
            INFORMATION['TITLE'] = ''

    except (urllib.error.HTTPError, ConnectionResetError,
            urllib.error.URLError):
        INFORMATION['TITLE'] = ''
        INFORMATION['SPEED'] = ''
    if DEBUG:
        print('get_statuscodes stop')


def get_ssl(domain, event_ip):
    """Get SSL cert."""
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
    """Get server information."""
    if DEBUG:
        print('get_srv start')
    try:
        site = requests.get('http://{}'.format(domain))
        try:
            INFORMATION['SERVER'] = site.headers['server']
        except KeyError:
            INFORMATION['SERVER'] = ''
    except requests.exceptions.RequestException:
        INFORMATION['SERVER'] = ''
    if DEBUG:
        print('get_srv stop')


def get_php(domain, event_ip):
    """Get php version."""
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
            size = round(int(result.headers['Content-length']) / 1024)
            INFORMATION['SIZE'] = '{} kB'.format(size)
        except KeyError:
            INFORMATION['SIZE'] = ''
    except requests.exceptions.RequestException:
        php = ''
    INFORMATION['PHP'] = php
    if DEBUG:
        print('get_php stop')


def page_speed(domain, event_ip):
    """Get ttfb and ttlb from url."""
    try:
        url = 'http://{}'.format(domain)
        opener = urllib.request.build_opener()
        request = urllib.request.Request(url)

        start = int(round(time.time() * 1000))
        resp = opener.open(request)
        # read one byte
        resp.read(1)
        INFORMATION['TTFB'] = int(round(time.time() * 1000)) - start
        # read the rest
        resp.read()
        INFORMATION['TTLB'] = int(round(time.time() * 1000)) - start
    except (urllib.error.HTTPError, urllib.error.URLError, http.client.HTTPException):
        INFORMATION['TTFB'] = ''
        INFORMATION['TTLB'] = ''


if __name__ == "__main__":
    main()

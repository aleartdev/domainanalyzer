#!/usr/bin/env python3
"""Get information on a domain name."""
# coding=utf-8
from datetime import datetime
import dns
from dns import resolver
import http.client
import lxml.html
import pythonwhois
import re
import requests
import socket
import sys
from threading import Thread
import threading
import time
import urllib
import ssl

# If you want pwhois to handle non standard characters in result
# you need to implement this fix on net.py in pythonwhois
# https://github.com/joepie91/python-whois/pull/59

# TODO Docker
# TODO Static type checking mypy http://mypy-lang.org/examples.html
# TODO Logging instead of debug
# TODO Class
# TODO JSON output flag overriding printout to console
# TODO status codes display requests.get(url, allow_redirects=False, timeout=0.5)
# TODO combine requests ?
# TODO get_statuscodes is named wrong
# TODO Where exception , AttributeError this is temporary and should prompt the user to try again

# SETTINGS
RES = resolver.Resolver()
RES.nameservers = ['8.8.8.8']
DEBUG = False
EVENT_IP = threading.Event()

# Information about the domain is asyncly gatherd here
INFO = {}
SUGGESTIONS = {'error': [], 'warning': [], 'notice': []}


def main():
    """Main."""
    _domain_ = get_argument(1, None)
    parse_search(_domain_)
    get_information()
    analyze()
    output_console()


def get_argument(index, return_except):
    """Get arguments."""
    try:
        return sys.argv[index]
    except IndexError:
        return return_except


def parse_search(search):
    """So the search can be converted to a domain."""
    INFO['SEARCH'] = search
    _domain_name_ = search.split("//")[-1].split("/")[0] if '//' in search else search
    INFO['DOMAIN NAME'] = _domain_name_
    # get punycode
    try:
        _domain_name_.encode(encoding='utf-8').decode('ascii')
    except UnicodeDecodeError:
        domain_punycode = _domain_name_.encode("idna").decode("utf-8")
    else:
        domain_punycode = ''
    INFO['IDN'] = domain_punycode


def get_information():
    """Get domain information and split work in to threads."""
    functions = [get_whois, get_wpadmin, get_statuscodes, page_speed, get_ssl,
                 get_srv, get_php, get_ip, get_host, get_mx, get_txt, get_ns]
    threads_list = list()
    for function in functions:
        threads_list.append(Thread(name=function, target=function,
                            args=(INFO['DOMAIN NAME'],)))

    for thread in threads_list:
        thread.start()

    for thread in threads_list:
        thread.join()


def analyze():
    """Analyze domain."""
    if INFO['TIME MODIFIED']:
        if INFO['TIME MOD DELTA'] < 2:
            SUGGESTIONS['warning'].append('DNS changed last 48 hours!')
        elif INFO['TIME MOD DELTA'] < 7:
            SUGGESTIONS['notice'].append('DNS changed last 7 days!')

    # notice slow site
    if INFO['TTLB']:
        if INFO['TTLB'] > 1000:
            if '5.' in INFO['PHP']:
                SUGGESTIONS['warning'].append('Slow site (Low PHP version)')
            elif INFO['PHP']:
                SUGGESTIONS['notice'].append('Slow site (Not PHP version)')
            else:
                SUGGESTIONS['notice'].append('Slow site (PHP version unknown)')

    if 'cloudflare' in INFO['SERVER']:
        SUGGESTIONS['notice'].append('Cloudflare!')

    # warning no host
    if not INFO['HOST'] and INFO['IP']:
        SUGGESTIONS['notice'].append('No host found for IP. (VPS/Dedicated IP/CLoudFlare)')

    # no ip
    if not INFO['IP']:
        SUGGESTIONS['error'].append('No IP (No A-pointer)')

    # status
    if 'ok' not in INFO['STATUS'].lower():
        SUGGESTIONS['warning'].append('Status code not "OK": {}'.format(INFO['STATUS']))

    # ssl
    if INFO['SSL'] == 'No':
        SUGGESTIONS['warning'].append('No SSL detected!')

    # spf
    if 'spf' not in INFO['TXT'].lower():
        SUGGESTIONS['warning'].append('No SPF record!')
    else:
        # SPF record exits
        if not any(host_ in INFO['TXT'] for host_ in [INFO['MX DOMAIN NAME'], host_domain(INFO['MX ORGANIZATION']), host_domain(INFO['MXHR'])]):
            SUGGESTIONS['warning'].append('Mail host not in SPF!')
        if INFO['IP'] not in INFO['TXT']:
            if INFO['IP'] is INFO['MXIP']:
                # warning: ip not in spf and site and mail on same server
                SUGGESTIONS['warning'].append('IP not in SPF!')
            else:
                # notice: ip not in spf and site and mail on different server
                SUGGESTIONS['notice'].append('IP not in SPF!')

    # mail
    try:
        if INFO['DOMAIN NAME HOST'] not in INFO['MXHR'] and INFO['MX DOMAIN NAME']:
            SUGGESTIONS['notice'].append('External mail hosted at {} ({})!'.format(INFO['MX DOMAIN NAME'], INFO['MX ORGANIZATION']))
    except KeyError:
        pass


def host_domain(host):
    """Return domain from host."""
    return '.'.join(host.split('.')[-2:])


def output_console():
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
    for key, value in sorted(INFO.items()):
        if value:
            if value is True:
                # make True visible in output
                value = 'Yes'
            print('{}{}{}{}'.format(color['bold'], "{:<17}".format(key),
                                    color['end'], value))
        else:
            print('{}{}{}{}'.format(color['bold'],
                                    key, color['end'], ''))
    for error_msg in SUGGESTIONS['error']:
        print('Error! {}{}{}{}'.format(color['bold'], color['red'],
                                       error_msg, color['end']))
    for warning_msg in SUGGESTIONS['warning']:
        print('Warning! {}{}{}{}'.format(color['bold'], color['yellow'],
                                         warning_msg, color['end']))
    for notice_msg in SUGGESTIONS['notice']:
        print('Notice! {}{}{}{}'.format(color['bold'], color['darkcyan'],
                                        notice_msg, color['end']))


def get_host(domain):
    """Get host from domain name."""
    # we must wait for ip to be avalible from other thread
    EVENT_IP.wait()
    if DEBUG:
        print('get_host start')
    global INFO
    try:
        INFO['HOST'] = socket.gethostbyaddr(INFO['IP'])[0]
        INFO['DOMAIN NAME HOST'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', INFO['HOST'])[0]
    except socket.error:
        INFO['HOST'] = ''
        INFO['DOMAIN NAME HOST'] = ''

    if DEBUG:
        print('get_host stop')


def get_txt(domain):
    """Get TXT from domain name."""
    if DEBUG:
        print('get_txt start')
    global INFO
    try:
        if INFO['IDN']:
            domain_dig = INFO['IDN']
        else:
            domain_dig = domain
        INFO['TXT'] = '\n\t\t '.join([txt.to_text() for txt in dns.resolver.query(domain_dig, 'TXT')])
    except (socket.error, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, AttributeError):
        INFO['TXT'] = ''
    if DEBUG:
        print('get_txt stop')


def get_ns(domain):
    """Get NS from domain name."""
    if DEBUG:
        print('get_ns start')
    global INFO
    try:
        if INFO['IDN']:
            domain_dig = INFO['IDN']
        else:
            domain_dig = domain
        INFO['NS'] = '\n\t\t '.join([ns.to_text() for ns in dns.resolver.query(domain_dig, 'NS')])
    except (socket.error, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        INFO['NS'] = ''
    if DEBUG:
        print('get_ns stop')


def get_mx(domain):
    """Get MX from domain name."""
    if DEBUG:
        print('get_mx start')
    global INFO
    try:
        # get mx from resolver and make list and make string
        INFO['MX'] = '\n\t\t '.join([mx.to_text() for mx in dns.resolver.query(domain, 'MX')])
        # get second word that ends with a dot excluding that dot
        INFO['MX HOST'] = re.findall(r'.* (.*).', INFO['MX'])[0]
        INFO['MX DOMAIN NAME'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', INFO['MX HOST'])[0]
    except (socket.error, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, AttributeError):
        INFO['MX'] = ''
        INFO['MX HOST'] = ''
        INFO['MX DOMAIN NAME'] = ''
    if DEBUG:
        print('get_mx stop')
    global RES
    if INFO['MX HOST']:
        try:
            INFO['MXIP'] = RES.query(INFO['MX HOST'])[0].address
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout,
                dns.exception.DNSException, dns.resolver.NoNameservers):
            INFO['MXIP'] = ''
    else:
        INFO['MXIP'] = ''

    if INFO['MXIP']:
        # get org name from MXIP
        try:
            _whois = pythonwhois.get_whois(INFO['MXIP'], True)
            INFO['MX ORGANIZATION'] = re.findall(r'([a-zA-Z0-9_-]*\.[a-zA-Z0-9_]*$)', _whois['emails'][0])[0]
        except (UnicodeDecodeError, ValueError, KeyError, AttributeError):
            INFO['MX ORGANIZATION'] = ''
        try:
            INFO['MXHR'] = socket.gethostbyaddr(INFO['MXIP'])[0]
        except socket.error:
            INFO['MXHR'] = ''
    else:
        INFO['MX ORGANIZATION'] = ''
        INFO['MXHR'] = ''
        INFO['MX ORGANIZATION'] = ''


def get_mxorg(domain):
    """Get organization from MX IP."""
    # we must wait for ip to be avalible from other thread
    EVENT_IP.wait()
    if DEBUG:
        print('get_mxorg start')
    global INFO
    try:
        try:
            whois_2 = pythonwhois.get_whois(INFO['IP'], True)
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
        INFO['MX ORGANIZATION'] = org
        if DEBUG:
            print('get_mxorg stop')

    except (dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        INFO['MX ORGANIZATION'] = ''


def get_whois(domain):
    """Get whois from domain name."""
    global INFO
    if DEBUG:
        print('get_whois start {}'.format(domain))
    if domain.count('.') > 1:
        domain = '.'.join(domain.split('.')[-2:])
    try:
        _whois = pythonwhois.get_whois(domain, True)
        if DEBUG:
            print('get_whois stop (success)')
    except UnicodeDecodeError:
        SUGGESTIONS['error'].append('Python whois UnicodeDecodeError. (Implement fix in readme.md https://github.com/freiholtz/domainanalyzer/blob/master/README.md)')
        _whois = []
        if DEBUG:
            print('get_whois (exception)')
    except pythonwhois.shared.WhoisException as e:
        SUGGESTIONS['error'].append('WhoisException - {}'.format(e))
        _whois = []

    try:
        INFO['TIME EXPIRE'] = _whois['expiration_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFO['TIME EXPIRE'] = ''

    try:
        INFO['TIME CREATED'] = _whois['creation_date'][0].strftime("%Y-%m-%d")
    except (KeyError, TypeError):
        INFO['TIME CREATED'] = ''

    try:
        INFO['TIME MODIFIED'] = _whois['updated_date'][0].strftime("%Y-%m-%d %H:%I:%S")
        _detla_datetime = datetime.now() - _whois['updated_date'][0]
        INFO['TIME MOD DELTA'] = round((_detla_datetime.seconds / 3600 / 24) + float(_detla_datetime.days), 2)
    except (KeyError, TypeError):
        INFO['TIME MODIFIED'] = ''
        INFO['TIME MOD DELTA'] = ''

    try:
        INFO['STATUS'] = ','.join(_whois['status'])
    except (KeyError, TypeError):
        INFO['STATUS'] = ''

    try:
        INFO['REGISTRAR'] = ' '.join(_whois['registrar'])
    except (KeyError, TypeError):
        INFO['REGISTRAR'] = ''

    if DEBUG:
        print('get_whois stop')


def get_ip(domain):
    """Get whois from domain name."""
    if DEBUG:
        print('get_ip start {}'.format(domain))
    ips = []
    try:
        answers = RES.query(domain)
        for rdata in answers:
            ips.append(rdata.address)
        INFO['IP'] = ips[0]
    except dns.resolver.NXDOMAIN:
        INFO['IP'] = ''
        INFO['DOMAIN NAME'] = ''
    except (dns.resolver.NXDOMAIN, dns.resolver.Timeout,
            dns.exception.DNSException):
        INFO['IP'] = ''

    if DEBUG:
        print('get_ip stop')
    EVENT_IP.set()


def get_wpadmin(domain):
    """Get Wordpress admin login status code."""
    if DEBUG:
        print('get_wpadmin start')
    try:
        result = requests.get('http://{}/wp-admin'.format(domain), timeout=5)
        if result.status_code == 200:
            INFO['WORDPRESS'] = True
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        INFO['WORDPRESS'] = False
    if DEBUG:
        print('get_wpadmin stop')


def get_statuscodes(domain):
    """Get main site status code."""
    if DEBUG:
        print('get_statuscodes start')
    try:
        html = urllib.request.urlopen('http://{}'.format(domain))
        site = lxml.html.parse(html)
        try:
            INFO['STATUS CODE'] = '{} / {}'.format(html.getcode(), requests.status_codes._codes[html.getcode()][0])
            INFO['TITLE'] = site.find(".//title").text
        except (AttributeError, AssertionError):
            INFO['TITLE'] = ''
    except (UnicodeDecodeError, urllib.error.HTTPError, ConnectionResetError, urllib.error.URLError, ssl.CertificateError):
        INFO['TITLE'] = ''
    if DEBUG:
        print('get_statuscodes stop')


def get_ssl(domain):
    """Get SSL cert."""
    if DEBUG:
        print('get_ssl start')
    try:
        requests.get('https://{}'.format(domain), verify=True, timeout=5)
        INFO['SSL'] = 'Yes'
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.TooManyRedirects):
        INFO['SSL'] = 'No'
    if DEBUG:
        print('get_ssl stop')


def get_srv(domain):
    """Get server information."""
    if DEBUG:
        print('get_srv start')
    try:
        site = requests.get('http://{}'.format(domain), timeout=5)
        try:
            INFO['SERVER'] = site.headers['server']
        except KeyError:
            INFO['SERVER'] = ''
    except requests.exceptions.RequestException:
        INFO['SERVER'] = ''
    if DEBUG:
        print('get_srv stop')


def get_php(domain):
    """Get php version."""
    if DEBUG:
        print('get_php start')
    try:
        result = requests.get('http://{}'.format(domain), timeout=5)
        try:
            php = result.headers['X-Powered-By']
            if 'php' not in php.lower():
                php = ''
        except KeyError:
            php = ''
        try:
            size = round(int(result.headers['Content-length']) / 1024)
            INFO['SIZE'] = '{} kB'.format(size)
        except KeyError:
            INFO['SIZE'] = ''
    except requests.exceptions.RequestException:
        php = ''
    INFO['PHP'] = php
    if DEBUG:
        print('get_php stop')


def page_speed(domain):
    """Get ttfb and ttlb from url."""
    try:
        url = 'http://{}'.format(domain)
        opener = urllib.request.build_opener()
        request = urllib.request.Request(url)

        start = int(round(time.time() * 1000))
        resp = opener.open(request)
        # read one byte
        resp.read(1)
        INFO['TTFB'] = int(round(time.time() * 1000)) - start
        # read the rest
        resp.read()
        INFO['TTLB'] = int(round(time.time() * 1000)) - start
    except (urllib.error.HTTPError, urllib.error.URLError, http.client.HTTPException, ssl.CertificateError):
        INFO['TTFB'] = ''
        INFO['TTLB'] = ''


if __name__ == "__main__":
    main()

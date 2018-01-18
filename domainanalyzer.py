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
# TODO: use second parameter to suggest solutions
# TODO: curl for ssl certificate

# Settings
UNKNOWN = r'¯\_(ツ)_/¯'
RESOVING_NAMESERVER = '8.8.8.8'

def main():
    """Main function"""

    # get the domain from arguments
    domain = get_argument(1, None)

    # get the problem from arguments
    problem = get_argument(2, None)

    # get information about the domain
    information = get_information(domain)
    
    # get suggestions on how to fix the domains problem
    suggestions = analyze(information, problem)
    
    # communicate suggestions to user
    output_console(suggestions)

def analyze(information, problem):
    """Get suggestions what can be fixed"""
    suggestions = []
    suggestions.append(information['domain_name'])
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

    # get only domain name
    information['domain_name'] = domain.split("//")[-1].split("/")[0] if '//' in domain else domain

    domain = information['domain_name']

    # get punycode
    try:
        domain.encode(encoding='utf-8').decode('ascii')
    except UnicodeDecodeError:
        domain_punycode = domain.encode("idna").decode("utf-8")
    else:
        domain_punycode = ''


    # resolve against google server to get more accurate whois
    res = resolver.Resolver()
    res.nameservers = [RESOVING_NAMESERVER]


    # init ip list for domain
    ips = []

    # if domain name is given
    if len(sys.argv) > 1:

        # get whois
        try:
            whois = pythonwhois.get_whois(domain, True)
        except UnicodeDecodeError:
            print('Python whois UnicodeDecodeError')
            whois = False

        # get php version
        php = UNKNOWN
        try:
            result = requests.get('http://{}'.format(domain))
            try:
                php = result.headers['X-Powered-By']
            except KeyError:
                pass
        except:
            pass

        # calculate days left
        try:
            daysleft = (whois['expiration_date'][0].date() - datetime.now().date()).days
        except (KeyError, TypeError):
            daysleft = False

        if daysleft:
            exp = '' if daysleft > 66 else whois['expiration_date'][0].strftime("%Y-%m-%d") + ' (' + str(daysleft) + ' days)'
        else:
            exp = UNKNOWN
    # calculate hours ago
        try:
            hoursago = round((datetime.now().date() - whois['updated_date'][0].date()).total_seconds() / 3600)
            mod = '' if hoursago > 48 else whois['updated_date'][0].strftime("%Y-%m-%d") + " (%g hours)" % round(hoursago, 0)
        except (KeyError, TypeError):
            mod = UNKNOWN

        try:
            status = ' '.join(whois['status'])
        except (KeyError, TypeError):
            status = UNKNOWN
        if status:
            print('STATUS\t{}'.format(status))
        if mod:
            print('MOD\t{}'.format(mod))
        if exp:
            print('EXP\t{}'.format(exp))
        try:
            print('REG\t{}'.format(' '.join(whois['registrar'])))
        except (KeyError, TypeError):
            pass
        try:
            print('DNS\t{}'.format(' '.join(whois['nameservers'])))
        except (KeyError, TypeError):
            pass
        try:
            print('PHP\t{}'.format(php))
        except (KeyError, TypeError):
            pass


        # get ip from domain
        try:
            answers = res.query(domain)
            for rdata in answers:
                ips.append(rdata.address)
            print('IP\t{}'.format(' / '.join(ips)))

            # get host from ip
            try:
                host = socket.gethostbyaddr(ips[0])
                print('HOST\t{}'.format(host[0]))
            except socket.error:
                print('HOST\t{}'.format(UNKNOWN))

            # get name from ip
            whois_2 = pythonwhois.get_whois(ips[0], True)
            try:
                print('ORG\t{}'.format(whois_2['contacts']['registrant']['name']))
            except (KeyError, TypeError):
                try:
                    print('ORG\t{}'.format(whois_2['emails'][0]))
                except KeyError:
                    print('ORG\t{}'.format(UNKNOWN))

        except dns.resolver.NXDOMAIN:
            print('ERR\tNo such domain (NXDOMAIN)')
        except dns.resolver.Timeout:
            print('ERR\tTimeout')
        except dns.exception.DNSException:
            print('ERR\tDNSException')

        mx_ = subprocess.check_output(['dig', '+noall', '+answer', 'MX', domain]).decode('unicode_escape').strip().replace('\n', '\n\t')
        if mx_:
            print('MX\t{}'.format(mx_))
        else:
            print('MX\t{}'.format(UNKNOWN))


        print('TXT\t{}'.format(subprocess.check_output(['dig', '+noall', '+answer', 'TXT', domain]).decode('unicode_escape').strip()))
        
        if domain_punycode:
            print('PUNY\t{}'.format(domain_punycode))
        # if you want to open domain in browser
        # webbrowser.open('http://' + DOMAIN)
        return information

def output_console(suggestions):
    """output suggestions to console"""
    for suggestion in suggestions:
        print(suggestion)

if __name__ == "__main__":
    main()

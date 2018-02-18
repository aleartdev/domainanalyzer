import pytest
import sys
import re
from domainanalyzer import domainanalyzer

ref_domain = 'davidfreiholtz.com'

domainanalyzer.parse_search(ref_domain)
domainanalyzer.get_information()
domainanalyzer.analyze()

def test_ref_domain():
    """Test ref domain againts known correct values"""
    assert domainanalyzer.INFO['DNS'] == 'dns1.oderland.com dns2.oderland.com dns3.oderland.com'
    assert domainanalyzer.INFO['DOMAIN NAME'] == 'davidfreiholtz.com'
    assert domainanalyzer.INFO['DOMAIN NAME HOST'] == 'oderland.com'
    assert domainanalyzer.INFO['HOST'] == 'premium15.oderland.com'
    assert domainanalyzer.INFO['IDN'] == ''
    assert domainanalyzer.INFO['IP'] == '91.201.60.73'
    assert any( _ in domainanalyzer.INFO['MX'] for _ in ['mx1.oderland.com', 'mx2.oderland.com'])
    assert domainanalyzer.INFO['MX DOMAIN NAME'] == 'oderland.com'
    assert '.oderland.com' in domainanalyzer.INFO['MX HOST']
    assert '.oderland.com' in domainanalyzer.INFO['MXHR']
    assert re.compile("(\d*\.\d*\.\d*\.\d*)").match(domainanalyzer.INFO['MXIP'])
    assert domainanalyzer.INFO['PHP'] == ''
    assert domainanalyzer.INFO['REGISTRAR'] == 'Key-Systems GmbH'
    assert domainanalyzer.INFO['SEARCH'] == 'davidfreiholtz.com'
    assert domainanalyzer.INFO['SERVER'] == 'Apache'
    assert re.compile("(\d*\ kB)").match(domainanalyzer.INFO['SIZE'])
    assert domainanalyzer.INFO['SSL'] == 'Yes'
    assert domainanalyzer.INFO['STATUS'] == 'ok https://icann.org/epp#ok'
    assert domainanalyzer.INFO['STATUS CODE'] == '200 / ok'
    assert re.compile("(\d{4}-\d{2}-\d{2})").match(domainanalyzer.INFO['TIME CREATED'])
    assert re.compile("(\d{4}-\d{2}-\d{2})").match(domainanalyzer.INFO['TIME EXPIRE'])
    assert re.compile("(\d{0,}\.\d{0,2})").match(str(domainanalyzer.INFO['TIME MOD DELTA']))
    assert re.compile("(\d{4}-\d{2}-\d{2}\ \d{2}:\d{2}:\d{2})").match(domainanalyzer.INFO['TIME MODIFIED'])
    assert 'David' in domainanalyzer.INFO['TITLE']
    assert re.compile("(\d*)").match(str(domainanalyzer.INFO['TTFB']))
    assert re.compile("(\d*)").match(str(domainanalyzer.INFO['TTLB']))
    assert any( _ in domainanalyzer.INFO['TXT'] for _ in ['v=spf1', domainanalyzer.INFO['IP'], domainanalyzer.INFO['MX DOMAIN NAME']])
    assert domainanalyzer.INFO['WORDPRESS'] == True

import pytest
import sys
from domainanalyzer import domainanalyzer

domainanalyzer.parse_search('davidfreiholtz.com')
domainanalyzer.get_information()
domainanalyzer.analyze()

def test_DOMAIN_NAME_HOST():
    """Test authors domain"""
    assert domainanalyzer.INFO['DOMAIN NAME HOST'] == 'oderland.com'

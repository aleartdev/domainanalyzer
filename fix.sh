#!/usr/bin/env bash
# https://github.com/joepie91/python-whois/issues/55#issuecomment-170874767
# Fix python whois error on .eu domains
sed -i '516s/.*/                   data.setdefault(\"registrar\", []).insert(0, match.group(1).strip())/' /usr/local/lib/python3.6/site-packages/pythonwhois/parse.py

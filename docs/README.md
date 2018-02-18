# domainanalyzer.py
# Python script to analyze a domain name from terminal to find out things like DNS, SSL, Registrar, Title and much more.

> The program uses threads to speed up fetching of information.

> A result might look like this
![domainanalyzer-readme-01.png](https://github.com/freiholtz/domainanalyzer/raw/master/docs/domainanalyzer-readme-01.png)


## Installation & test run

* mkdir ~/domainanalyzer && cd ~/domainanalyzer
* git clone https://github.com/freiholtz/domainanalyzer.git
* virtualenv venv && source venv/bin/activate
* pip3 install -r requirements.txt
* echo "alias s=\"source ~/domainanalyzer/venv/bin/activate && python3 ~/domainanalyzer/src/domainanalyzer/domainanalyzer.py\"" >> ~/.bash_profile
* source ~/.bash_profile
* s davidfrehioltz.com

## Fix Python Whois encoding problems

* Implement this fix on net.py https://github.com/joepie91/python-whois/pull/59/files?diff=unified
* To locate net.py run this command: find ~/domainanalyzer -name "net.py"
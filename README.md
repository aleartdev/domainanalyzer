# domainanalyzer
# Python script to analyze a domain name from terminal to find out things like DNS, SSL, Registrar, Title and much more.

> Analyze a domain name to get data  about it and give feedbak to user in the form of data and notices , warnings, and errors.

> A result might look like this
![domainanalyzer-readme-01.png](https://github.com/freiholtz/domainanalyzer/raw/master/domainanalyzer-readme-01.png)


## Installation

* mkdir ~/domainanalyzer && cd ~/domainanalyzer
* git clone https://github.com/freiholtz/domainanalyzer.git
* virtualenv venv && source venv/bin/activate
* pip3 install -r requirements.txt
* echo "alias s=\"source ~/domainanalyzer/venv/bin/activate && python3 ~/domainanalyzer/domainanalyzer.py\"" >> ~/.bash_profile
* source ~/.bash_profile
* s davidfrehioltz.com
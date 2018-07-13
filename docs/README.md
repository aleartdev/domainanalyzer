# Domainanalyzer
# Python script to analyze a domain name and fetch all relevant information for trouble shooting.

> The script uses threads to speed up fetching of information.

A result might look like this

![domainanalyzer-readme-01.png](https://github.com/freiholtz/domainanalyzer/raw/master/docs/domainanalyzer-readme-01.png)


## Installation instructions

Requires: Docker (Install from here https://store.docker.com/search?type=edition&offering=community )

Step 1: Clone the repository
```
cd && git clone https://github.com/freiholtz/domainanalyzer.git
```

Step 2: Install alias to start docker container to your .bash_profile for ease of use
```
echo "alias domainanalyzer=\"bash ~/domainanalyzer/start\"" >> ~/.bash_profile && source ~/.bash_profile
```

Example use inside docker container
```
s davidfrehioltz.com
```

## Fix Python Whois encoding problems

* Implement this fix on net.py https://github.com/joepie91/python-whois/pull/59/files?diff=unified
* To locate net.py run this command:
```
find ~/domainanalyzer -name "net.py"
```
* Or of you dont use venv you might need to run this command:
```
find ~/ -name "net.py"
```
You might experince problems after editing due to spaces/tabs conflict.
Default indentation is tabs in the file but you probably have spaces in your IDE

## I don't have PIP3 on my shared hosting
* Check with your hosting if they have a official way of using PIP3. Mine for example requires you to create a Python app in the control panel to get a venv preinstalld with PIP3.

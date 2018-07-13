# Domainanalyzer
# Dockerized Python script that analyzes a domain name and fetchs all relevant information relevant for hosting support

> Uses threads to speed up fetching of information.

A result might look like this

![domainanalyzer-readme-01.png](https://github.com/freiholtz/domainanalyzer/raw/master/docs/domainanalyzer-readme-01.png)


## Installation instructions

Step 1: Install Docker if you don't have it
```
https://store.docker.com/search?type=edition&offering=community
```

Step 2: Run this command in the terminal app to get the source file and create a docker image and a shortcut dommand
```
cd && git clone https://github.com/freiholtz/domainanalyzer.git && cd domainanalyzer && ./install && echo "alias s=\"docker run freiholtz/domainanalzer \"" >> ~/.bash_profile && source ~/.bash_profile
```

Step 3: Use the alias command and a domain name to get the information
```
s davidfrehioltz.com
```

# DONE!

## Fix Python Whois encoding problems

This fix might not be compatible with dockerization

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

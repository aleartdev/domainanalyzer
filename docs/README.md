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
cd && git clone https://github.com/freiholtz/domainanalyzer.git && cd domainanalyzer && ./install && echo "alias s=\"docker run freiholtz/domainanalzer \"" >> ~/.bash_profile && source ~/.bash_profile && s davidfreiholtz.com
```

# DONE! Use S and a domainname to do a search!

## Fix Python Whois encoding problems with non-standard-chars domains

* Implement this fix on net.py https://github.com/joepie91/python-whois/pull/59/files?diff=unified
* To locate net.py run this command (inside your python enviroment in the docker container):
```
find ~/domainanalyzer -name "net.py"
```
You might experince problems after editing due to spaces/tabs conflict.
Default indentation is tabs in the file but you probably have spaces in your IDE

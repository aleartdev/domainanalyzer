# Domainanalyzer
> Dockerized Python script that analyzes a domain name and fetchs all relevant information for hosting support
> Multi threaded fetching makes it super-fast.

## Installation instructions

Step 1: Install Docker if you don't have it
```
https://store.docker.com/search?type=edition&offering=community
```
Step 2: Use bash for this
```
bash
```

Step 3: Run this terminal command in the folder you want to save the app in
```
docker run --rm -it -v ${PWD}:/project --workdir /project alpine/git clone https://github.com/freiholtz/domainanalyzer.git ; cd domainanalyzer ; ./install ;echo "Run with: docker run --rm freiholtz/domainanalzer davidfreiholtz.com"
```

## Usage

If you crate a alias/abbrivation s for the run command you can analyze a domain like this.
```
s davidfreiholtz.com
```

A result might look like this

![domainanalyzer-readme-01.png](https://github.com/freiholtz/domainanalyzer/raw/master/docs/domainanalyzer-readme-01.png)


## If you get errorrs on domains with with non-standard-chars the solution might be..

> This is for advanced users

* Implement this fix on net.py https://github.com/joepie91/python-whois/pull/59/files?diff=unified
* To locate net.py run this command (inside your python enviroment in the docker container):
```
find ~/domainanalyzer -name "net.py"
```
You might experince problems after editing due to spaces/tabs conflict.
Default indentation is tabs in the file but you probably have spaces in your IDE

# Domainanalyzer
# Python script to analyze a domain name and fetch all relevant information for trouble shooting.

> The script uses threads to speed up fetching of information.
> And unittest for safe development.

A result might look like this

![domainanalyzer-readme-01.png](https://github.com/freiholtz/domainanalyzer/raw/master/docs/domainanalyzer-readme-01.png)


## Installation instructions

Open your terminal!

Create a folder
```
mkdir ~/domainanalyzer && cd ~/domainanalyzer
```
Clone the repository
```
git clone https://github.com/freiholtz/domainanalyzer.git
```
Install virtualenv if not on your enviroment
```
pip3 install virtualenv
```
Careate and activate a virtual enviroment so you dont litter your computer
```
virtualenv venv && source venv/bin/activate
```
Install required modules in your virtual enviroment
```
pip3 install -r requirements.txt
```
Add a sick alias to your .bash_profile for ease of use
```
echo "alias s=\"source ~/domainanalyzer/venv/bin/activate && python3 ~/domainanalyzer/src/domainanalyzer/domainanalyzer.py\"" >> ~/.bash_profile
```
Source your .bash_profile to get access to the alias
```
source ~/.bash_profile
```
With you new awsome alias try out a search on my domain!
```
s davidfrehioltz.com
```

## Fix Python Whois encoding problems

* Implement this fix on net.py https://github.com/joepie91/python-whois/pull/59/files?diff=unified
* To locate net.py run this command:
```
find ~/domainanalyzer -name "net.py"
```

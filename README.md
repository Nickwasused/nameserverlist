# nameserverlist
# Generate Files

```pip3 install -r requirements.txt```  
```python3 main.py tld```  
```python3 main.py root```  
```python3 main.py public```  
```python3 main.py suffix```  
```python3 main.py domains```  

# Pregenrated files

https://github.com/Nickwasused/nameserverlist/releases/latest/download/nsroot.json  
https://github.com/Nickwasused/nameserverlist/releases/latest/download/nstld.json  
https://github.com/Nickwasused/nameserverlist/releases/latest/download/public_dns.json  
https://github.com/Nickwasused/nameserverlist/releases/latest/download/nspublicsuffix.json  
https://github.com/Nickwasused/nameserverlist/releases/latest/download/nsdomains.json

# Results

See `json/` or https://github.com/Nickwasused/nameserverlist/releases/latest

* nsdomains.json - NS for spesific domains given in `domains.txt`
* nsroot.json - all root NSs http://www.internic.net/domain/named.root
* nstld.json - all TLDs from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
* public_dns.json - a manual list generated from `public_dns.txt`

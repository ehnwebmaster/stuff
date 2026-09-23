<div align="center">

# List of DDoS attacks

**Automatically reported banned IPs from fail2ban and CloudFlare WAF from [elhacker.NET](https://elhacker.net)**


</div>

---

## Overview

Two lists:

Auto-update **WAF CloudFlare** blocklist last 24 hours
https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.txt

Auto-update **fail2ban** blocklist
https://github.com/ehnwebmaster/stuff/blob/main/fail2ban-drops.txt

Works with **iptables** or ipset — Linux, OPnsense, etc (use drop or reject)

### How It Works

```
Attacker → fail2ban or CloudFlare from WAF detects abuse → updates the two lists every x minutes
```

1. **WAF CloudFlare** detects events from the firewall CloudFlare using API GraphQL including layer 7 DDoS, Rate Limit and WAF events including custom rules (excluding IP's from Tor and 10 or more hits and sorted by hits)
2. **fail2ban** detects too much pettitions in short range of time or 404 pettitions from our web server




## The two ban lists

Fail2Ban
- ```https://github.com/ehnwebmaster/stuff/blob/main/fail2ban-drops.txt```

CloudFlare Firewall WAF
- ```https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.txt```


## Download

Just copy download raw link

```bash
https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/fail2ban-drops.txt
```
Remember the CloudFlare WAF List contains the IP's sorted from more abusive (more hits on top) to less abusive (less hits at bottom)
Only IPv4, we remove the IPv6 IP's

```bash
https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/ips_bloqueadas.txt
```


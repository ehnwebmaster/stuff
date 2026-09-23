<div align="center">

# List of attackers DDoS

**Automatically report banned IPs from fail2ban and CloudFlare WAF from [elhacker.NET](https://elhacker.net)**


</div>

---

## Overview

Two lists:

Auto-update **WAF CloudFlare** blocklist last 24 hours
https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.txt

Auto-update **fail2ban** blocklist
https://github.com/ehnwebmaster/stuff/blob/main/fail2ban-drops.txt

Works with **iptables** or ipset — Linux, OPnsense, etc

### How It Works

```
Attacker → fail2ban or CloudFlare from WAF detects abuse → updates the two lists every x minutes
```

1. **WAF CloudFlare** detects events from the firewall CloudFlare using API GraphQL including layer 7 DDoS, Rate Limit and WAF events (excluding IP's from Tor)
2. **fail2ban** detects too much pettitions in short range of time or 404 pettitions from our web server




## The two lists

- ```https://github.com/ehnwebmaster/stuff/blob/main/fail2ban-drops.txt```
- ```https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.txt```


## Download


```bash
https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/fail2ban-drops.txt
```

```bash
https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.tx
```


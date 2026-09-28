<div align="center">

# List of DDoS attacks

**Automatically reported banned IPs from fail2ban and CloudFlare WAF from [elhacker.NET](https://elhacker.net)**

<img src="https://blog.cloudflare.com/_image?href=https%3A%2F%2Fblog.cloudflare.com%2F_emdash%2Fapi%2Fmedia%2Ffile%2F01KW46Q3ZX87F6RB3S7E1E615J.png&w=1801&h=1013&f=webp&fit=cover&position=center" width="300">
</div>

---

## Overview

Two lists:

Auto-update **WAF CloudFlare** blocklist last 24 hours updated every 4 minutes
https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.txt

Auto-update **fail2ban** blocklist
https://github.com/ehnwebmaster/stuff/blob/main/fail2ban-drops.txt

Works with **ipset** (iptables) — Linux, OPnsense, etc (use drop or reject) or **CloudFlare Lists** (see examples)

### How It Works

```
Attacker → fail2ban or CloudFlare from WAF detects abuse → updates the two lists every x minutes
```

1. **WAF CloudFlare** detects events from the firewall CloudFlare using API GraphQL including layer 7 DDoS, Rate Limit and WAF events including custom rules (excluding IP's from Tor and 10 or more hits and sorted by hits)
2. **fail2ban** detects too much pettitions in short range of time, 404 pettitions, modSecurity rules hits.


## The two ban lists

CloudFlare Firewall WAF
- ```https://github.com/ehnwebmaster/stuff/blob/main/ips_bloqueadas.txt```

Fail2Ban
- ```https://github.com/ehnwebmaster/stuff/blob/main/fail2ban-drops.txt```


## Download

Just copy the download raw link:


a) _WAF_: Only IPv4, we remove the IPv6 IP's, no more than 10K Ip's

Remember the CloudFlare WAF List contains the IP's sorted from more abusive (more hits on top) to less abusive (less hits at bottom)

```bash
https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/ips_bloqueadas.txt
```

b) _Fail2ban_

```bash
https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/fail2ban-drops.txt
```

## Examples (How to use it)

Example ipset:

```
sudo ipset create blocked hash:net maxelem 10000
curl -s https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/ips_bloqueadas.txt | \
grep -E -v '^(#|$)' | \
sed 's/^/add blocked /' | \
sudo ipset restore
```

Cronjob for updates:

> sudo nano /usr/local/bin/update_blocked_ips.sh

```
#!/bin/bash

URL="https://raw.githubusercontent.com/ehnwebmaster/stuff/refs/heads/main/ips_bloqueadas.txt"
SET_NAME="blocked"
TEMP_SET_NAME="blocked_tmp"

# 1. Crear el conjunto temporal si no existe y limpiarlo
ipset create $TEMP_SET_NAME hash:net maxelem 10000 -exist
ipset flush $TEMP_SET_NAME

# 2. Cargar las IPs en el conjunto temporal
curl -s "$URL" | grep -E -v '^(#|$)' | sed "s/^/add $TEMP_SET_NAME /" | ipset restore

# 3. Crear el conjunto principal si no existe
ipset create $SET_NAME hash:net maxelem 1000 -exist

# 4. Asegurar la regla de iptables
iptables -C INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null || \
iptables -I INPUT -m set --match-set $SET_NAME src -j DROP

# 5. Intercambiar de forma atómica la lista vieja por la nueva
ipset swap $TEMP_SET_NAME $SET_NAME

# 6. Eliminar la lista temporal
ipset destroy $TEMP_SET_NAME

echo "[$(date)] Lista de IPs bloqueadas actualizada con éxito."
```

> sudo chmod +x /usr/local/bin/update_blocked_ips.sh
> sudo crontab -e
> 0 3 * * * /usr/local/bin/update_blocked_ips.sh >> /var/log/ipset_update.log 2>&1

And then:

> sudo iptables -I INPUT -m set --match-set blocked src -j DROP

CloudFlare -> Manage Account -> Configurations -> Lists

`Copy - Paste all the IP's`

Example expression WAF:

> (ip.src in $list)

And choose action: Managed Challange or Block


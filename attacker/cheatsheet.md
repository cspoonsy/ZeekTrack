# ChooChoo Attacker — Tools and Targets

You're inside a Kali container on the same Docker network as the target.
Your goal: figure out what's running, then disrupt the train.

## Where am I?

```sh
ip -br a       # your address
ip route       # the network you're on
```

## What's available

```
nmap, ncat, tcpdump          # network recon + capture
mosquitto-clients            # publish/subscribe client
mbpoll, pymodbus (Python)    # industrial protocol client
smbclient                    # file-share client
curl, jq                     # HTTP
python3 (with paho-mqtt + pymodbus pre-installed)
vim-tiny, less
```

## Where to look first

Ask your trainer for the network range to scan if you don't know it.
Otherwise, check the routes above and start from there.

## Hints

- If you find an open port, fingerprint it: `nmap -sV -p <port> <host>`
- Industrial / IoT protocols are usually plaintext — `tcpdump -A -s0` is your friend
- Read the manuals: `man mbpoll`, `man mosquitto_sub`, `man mosquitto_pub`

Good luck.

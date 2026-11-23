# trapsnmp2

trapsnmp2 follows [trapsnmp](https://github.com/etealgeria-ai/trapsnmp) and adds a few fixes on top: the console is not access-logged, upstream outages are logged once, the upstream client closes when forwarding is switched off, only the newest 100 rejected client certificates are kept, EVENTS_COUNT wraps within UInt32, and Diagnose reconnects its loopback OPC UA session. The Python package is still `trapsnmp`, so it runs the same way.

Comments in this README were made by Grok.

Python gateway that receives SNMP traps and informs, then publishes each one as OPC UA variables and a `SnmpTrapEvent`.

Supports SNMPv1, SNMPv2c, and SNMPv3 (`noAuthNoPriv`, `authNoPriv`, `authPriv`). SNMPv3 auth can be MD5, SHA, or SHA-256. Privacy can be DES or AES-128. A known user is localized to whatever engine ID the sender uses.

## Run

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python -m trapsnmp
```

- Console: `http://127.0.0.1:8080/` — sign in with password `P@ssw0rd`
- SNMP traps: UDP 162, or 1162 if 162 is unavailable
- OPC UA: `opc.tcp://127.0.0.1:4840/trapsnmp/`
- Namespace: `urn:trapsnmp:snmp`

The default SNMPv3 user is `trapsnmp`, authPriv, SHA passphrase `trapsnmp-auth`, AES passphrase `trapsnmp-priv`. Communities `public` and `private` are accepted. More communities and users can be added from the console.

Each trap is written under `Objects/trapsnmp` (`Latest.*`, recent slots, gateway counters) and raised as `SnmpTrapEvent`. The trap-tag driver also latches `TRAP_V1` / `TRAP_V2C` Booleans, fills each tag's virtual table, and queues the message at `EVENTS_001`. Write false to a Boolean to arm the next change. An optional upstream client can also write the trap JSON to another OPC UA node.

The built-in SNMP agent answers Get, GetNext, GetBulk, and Set on UDP 1161, and can forward the latest trap to configured destinations.

## GE Orbit radios

The Radios page polls a GE Orbit LN master (`mIfLnStatusConnRemTable`) and writes each connected radio into `Remote1` through `Remote255`. Every remote has the short tags (`remote_mac`, `remote_ip`, `rssi`, `down`, `if_index`) plus one tag per column of `mIfLnStatusConnRemEntry` in MDS-IF-LN-MIB. The master IP, community, port, and poll interval are set on the Config page.

The Send page can simulate those columns for Remote1 through Remote255 on one RSSI sine wave, with a random offset per remote. The wave period is 30 seconds and the step is 10 seconds. It stays stopped until you start it.

## OPC UA security

The server still accepts an anonymous session on security None. It also offers Basic256Sha256, Aes128-SHA256-RSA-OAEP, and Aes256-SHA256-RSA-PSS, in Sign and SignAndEncrypt. The application certificate is created on first start under `data/pki/own/`. A client certificate that is not trusted is stored in `data/pki/rejected` and can be accepted from the Publish page. Accepted certificates are stored in `data/pki/trusted/certs`. Accept, reject, and delete are written to disk and loaded again on the next start.

A username token is offered as well. On the open endpoint the password is encrypted with Basic256Sha256 and the server certificate. The first user is `trapsnmp` / `trapsnmp`.

## Settings

Communities, SNMPv3 users, the GE master, the agent, tag filters, upstream OPC UA, OPC UA users, and the last remote values are stored in `data/trapsnmp.ini` and loaded on the next start. The file is mode `0600`. Set `TRAPSNMP_DATA` to choose that folder. Otherwise an existing `/workspace/data` is used, then `./data`. The private key is not written into that file.

The console password is `P@ssw0rd`. It is stored in `[console]` of `data/trapsnmp.ini`. Use `P@ssw0rd` to sign in. Edit that line and restart only if you want a different password. Ten wrong passwords from one address lock it out for 5 minutes. Wrong passwords are forgotten after an hour, and a sign-in lasts 12 hours. The console is plain HTTP, so use it on a trusted network or behind an HTTPS proxy.

The RSSI sine stays stopped at startup. Start it from the Send page. Each step is 10 seconds.

## Running continuously

- Memory stays flat under steady trap traffic. Lists, logs, sessions, and queues all have fixed sizes.
- Each new trap OID or port number adds about 21 OPC UA nodes under `Tags`, and they are kept until restart. After 2,000 such addresses (about 42,000 nodes), new ones get no `TRAP_` tags; their traps still reach `Latest`, `Recent`, `EVENTS_001`–`EVENTS_010`, and the event, and the trace says "trap tag limit reached". Raise `MAX_TRAP_TAGS` in `trap_tags.py` if your devices need more.
- Each SNMPv3 sender engine ID gets its own copy of the user; at most 1,024 are kept, oldest dropped first.
- The OPC UA certificate is valid for 15 years. Within 30 days of expiry the gateway warns once a day in the log and trace, and a restart renews it (clients then trust the new one).
- An unreachable GE master is logged once when polling starts failing and once when it recovers.
- Logs go to standard output. Run the gateway under systemd or another service manager that rotates logs. Console requests are not logged, and an upstream OPC UA outage is logged once when it starts and once when it recovers.
- Only the newest 100 rejected OPC UA client certificates are kept in `data/pki/rejected`.
- The last remote values are saved at most once a minute (about 130 KB with 255 remotes, roughly 200 MB of writes a day). That is fine for SSD or industrial flash; on a plain SD card, raise the 60-second interval in `Service.persist`.
- The RSSI sine writes about 300 OPC UA nodes per trap (255 traps every 10 s). Leave it off on a production gateway.

## Soak test

`tools/soak_test.py` checks that a running gateway stays flat over a long run. It sends 5 SNMPv2c traps a second, records the gateway's memory, open files, and threads every 5 minutes, and prints FLAT or POSSIBLE LEAK at the end. It needs only the Python standard library (psutil on systems without `/proc`).

```bash
python3 tools/soak_test.py --pid $(pgrep -f "python.* -m trapsnmp") --hours 48 \
  --console http://127.0.0.1:8080 --password 'P@ssw0rd'
```

Add `--target 127.0.0.1:1162` if the receiver listens on UDP 1162. Samples go to `soak.csv`; Ctrl+C stops early and still prints a verdict.

# trapsnmp2

A debugged copy of [trapsnmp](https://github.com/etealgeria-ai/trapsnmp). The Python package is still called `trapsnmp`, so it runs the same way. See [Fixes in trapsnmp2](#fixes-in-trapsnmp2) below.

Comments in this README were made by Grok.

Python gateway that receives SNMP traps and informs, then publishes each one as OPC UA variables and a `SnmpTrapEvent`.

Supports SNMPv1, SNMPv2c, and SNMPv3 (`noAuthNoPriv`, `authNoPriv`, `authPriv`). SNMPv3 auth can be MD5, SHA, or SHA-256. Privacy can be DES or AES-128. A known user is localized to whatever engine ID the sender uses.

## Run

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python -m trapsnmp
```

- Console: `http://127.0.0.1:8080/`
- SNMP traps: UDP 162, or 1162 if 162 is unavailable
- OPC UA: `opc.tcp://127.0.0.1:4840/trapsnmp/`
- Namespace: `urn:trapsnmp:snmp`

The default SNMPv3 user is `trapsnmp`, authPriv, SHA passphrase `trapsnmp-auth`, AES passphrase `trapsnmp-priv`. Communities `public` and `private` are accepted. More communities and users can be added from the console.

Each trap is written under `Objects/trapsnmp` (`Latest.*`, recent slots, gateway counters) and raised as `SnmpTrapEvent`. The trap-tag driver also latches `TRAP_V1` / `TRAP_V2C` Booleans, fills each tag's virtual table, and queues the message at `EVENTS_001`. Write false to a Boolean to arm the next change. An optional upstream client can also write the trap JSON to another OPC UA node.

The built-in SNMP agent answers Get, GetNext, GetBulk, and Set on UDP 1161, and can forward the latest trap to configured destinations.

## GE Orbit radios

The Radios page polls a GE Orbit LN master (`mIfLnStatusConnRemTable`) and writes each connected radio into `Remote1` through `Remote999`. Every remote has the short tags (`remote_mac`, `remote_ip`, `rssi`, `down`, `if_index`) plus one tag per column of `mIfLnStatusConnRemEntry` in MDS-IF-LN-MIB. The master IP, community, port, and poll interval are set on the Config page.

The Send page can simulate those columns for Remote1 through Remote999 on one RSSI sine wave, with a random offset per remote.

## OPC UA security

The server still accepts an anonymous session on security None. It also offers Basic256Sha256, Aes128-SHA256-RSA-OAEP, and Aes256-SHA256-RSA-PSS, in Sign and SignAndEncrypt. The application certificate is created on first start under `data/pki/own/`. A client certificate that is not trusted is stored in `data/pki/rejected` and can be trusted from the Publish page.

A username token is offered as well. On the open endpoint the password is encrypted with Basic256Sha256 and the server certificate. The first user is `trapsnmp` / `trapsnmp`.

## Settings

Communities, SNMPv3 users, the GE master, the agent, tag filters, upstream OPC UA, the sine switch, OPC UA users, and the last remote values are stored in `data/trapsnmp.ini` and loaded on the next start. The private key is not written into that file. Remote values are saved at most once a minute; configuration changes are saved immediately.

The data folder is `TRAPSNMP_DATA` if that variable is set, otherwise `/workspace/data` if it already exists (older installs), otherwise `data/` under the working directory. The path is logged at startup.

## Fixes in trapsnmp2

- Settings and certificates no longer require `/workspace/data`; the gateway used to crash at start on machines without it. See the data folder note above.
- The GE Orbit poller reuses one SNMP engine. A new engine per poll left a UDP socket and a timer task running every time.
- The poller keeps up to 999 remotes, matching `Remote1`–`Remote999` (it stopped at 256).
- Remote values are saved once a minute instead of every 2 seconds, and the settings file is written atomically.
- The radio poller and the RSSI sine keep running after a failed step instead of stopping silently.
- Upstream OPC UA forwarding uses one connection at a time, times out after 2 s, and pauses 10 s after a failure, so a dead upstream no longer stalls every trap.
- Console test traps: SNMPv1 enterprise-specific traps are no longer reported as "not accepted", and a look-alike trap cannot be mistaken for the one just sent.
- Removing an agent community now stops it from working right away.
- Console POST requests must be `application/json`, which blocks cross-site form posts.
- OPC UA passwords with non-ASCII characters work; the private key file is `0600`; an expired application certificate is replaced at start.
- `Recent` has its own folder in the OPC UA browser instead of showing under Tags.
- The console makes one `/api/state` request at a time, and the response no longer carries every remote twice.

Not changed yet: the console still has no login and listens on all interfaces, and the RSSI sine still sends 999 loopback traps every 2 s.

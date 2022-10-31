# Juniper Config Cheat Sheet
## Created by Chris Murray
## Updated 210928


&nbsp;
## Initial Configuration
---
### login as root
#(all)
```
cli
configure
```

### master password
#(all)
```
set system master-password plain-text-password
```

### stop image auto upgrage
#(ex)
```
delete chassis auto-image-upgrade
```

### commit
```
commit
#or
commit confirmed <num minutes>
```

### set root password
#(all)
```
set system root-authentication plan-text-password
```



### upgrade firmware
#(ex)
    ### storage cleanup
    #(all)
    ```
    request system storage cleanup
    ```

    ### set date for failed cert check
    #(ex)
    ```
    set date 201107071700.00
    ```

* from shell 
    ```
    request shell
    mount_msdosfs /dev/<device> /mnt
    cp /mnt/<image file> /tmp
    cli
    ```
 * from ssh
    ```
    scp <image file> <user>@<remote ip>:/tmp/
    ```


* install
    ```
    request system software add /mnt/<image file>
    ```


### set hostname
```
set system host-name <name>
```

### default route
```
set routing-options static route 0.0.0.0/0 next-hop <gw address>
```

### default vlans
#(ex,qfx)
```
delete vlans default

set vlans blackhole vlan-id 999

set vlans native vlan-id 998
```
### default irb
#(ex,qfx)
```
delete interface irb.0
```

### dns
#(all)
```
set system name-server <dns1 ip>
set system name-server <dns2 ip>
```

### ntp
#(all)(stig-ndm)
```
set system ntp server <ntp1_ip> prefer
set system ntp server <ntp2_ip>
set system  time-zone UTC
```

### console
#(all)(stig-ndm)
```
set system ports console log-out-on-disconnect
set system ports console type vt100
set system ports auxiliary disable
set system ports auxiliary insecure
```

### login
#(all)(stig-ndm)
```
set system login password minimum-length 15
set system login password minimum-upper-cases 1
set system login password minimum-lower-cases 1
set system login password minimum-numerics 1
set system login password minimum-punctuations 1

set system login retry-options tries-before-disconnect 3
set system login retry-options lockout-period 15

set system login class superuser-local idle-timeout 10 permissions all

set system login class ADMIN idle-timeout 10 permissions admin-control

set system login class AUDITOR permissions [configure view-configuration]
set system login class AUDITOR allow-configuration "(system syslog)"

set system login class SR_ENGINEER permissions all
set system login class SR_ENGINEER deny-configuration "(system syslog)"

set system login class JR_ENGINEER permission all
set system login class JR_ENGINEER deny-configuration "(system syslog)"
set system login class JR_ENGINEER deny-commands "(file delete)"
set system login class JR_ENGINEER deny-commands "(request system software)"
```

### backup
#(all)(stig-ndm)
```
set system archival configuration transfer-on-commit archive-sites "scp://<service_account>@<backup server ip>:<file_path>" password "password"
```

### ssh 
#(all)(stig-ndm)
```
set system services ssh
set system services ssh protocol-version v2
set system services ssh client-alive-count-max 1
set system services ssh client-alive-interval 600
set system services ssh macs [hmac-sha2-256 hmac-sha2-512]
set system services ssh ciphers aes128-cbc
set system services ssh root-login deny 

show system users no-resolve
request system logout terminal <tty>
```

### syslog
#(all)(stig-ndm)
```
set system syslog host <syslog ip> any any
set system syslog host <syslog ip> any info
set system syslog source-address <mgmt ip>
```

### snmp
#(all)(stig-ndm)
```
set snmp v3 usm local-engine user servicevr authentication-sha authentication-password <auth pass>
set snmp v3 usm local-engine user servicevr privacy-aes128 privacy-password <priv pass>
set snmp v3 vacm security-to-group security-model usm security-name servicevr group readonly
set snmp v3 vacm access group readonly default-context-prefix security-model usm security-level privacy read-view ro
set snmp view ro oid 1 include
set snmp engine-id local <mgmt ip>
set snmp view ro oid 1 include
```

### audit
#(all)(stig-ndm)
```
set system syslog file LOG_FILE any any
set system syslog file LOG_FILE any info
set system syslog file LOG_FILE security info
set system syslog file LOG_FILE interactive-commands any
set system syslog file LOG_FILE change-log info
set system syslog file LOG_FILE authorization info
set system syslog file LOG_FILE firewall info
set system syslog file LOG_FILE authorization info
set system syslog file LOG_FILE archive files 12 size 1000000

set system syslog host <syslog ip> any info
set system syslog host <syslog ip> any critical
```



#interfaces
### access
```
set interfaces <interface> unit 0 family ethernet-switching
set interfaces <interface> unit 0 family ethernet-switching inteface-mode access 
set interfaces <interface> unit 0 family ethernet-switching vlan members <vlan1>
set interfaces <interface> unit 0 description <description>
```

### ae
```
set groups AE-SETTINGS interfaces <*> mtu 9196 aggregated-ether-options minimum-links 1 lacp active periodic fast

set interface <ae interface> apply-groups AE-SETTINGS
set chassis aggregated-devices ethernet device-count <total ae interface count>
wildcard range delete interfaces <interfaces to be added to ae>
wildcard range delete protocols rstp interface <interfaces to be added to ae>
wildcard range set interfaces <interfaces to be added to ae> ether-options 802.3ad <ae interface>
set interfaces <ae interface> description <remote_switch>-><remote interface>
set interfaces <ae interface> aggregated-ether-optins lacp active

```

### irb
```
set interface irb unit <irb id> family inet address <cidr>
```

### l3
```
set interface <interface> unit 0 family inet address <cidr>
```

### trunk
```
set interfaces <interface> unit 0 family ethernet-switching
set interfaces <interface> unit 0 family ethernet-switching inteface-mode trunk 
set interfaces <interface> unit 0 family ethernet-switching vlan members [<vlan1> <vlan2>]
set interfaces <interface> unit 0 description <remote_switch_name>-><remote_switch_port>
set interfaces <interface> native-vlan-id <native vlan id>
```


















### virtual chassis
#(ex,qfx)
* create vc port
    ```
    run request virtual-chassis vc-port set pic-slot <pic> port <port>

    delete protocols rstp <interface>
    ```
* delete vc port
    ```
    run request virtual-chassis vc-port delete pic-slot <pic> port <port>
    ```



### apply groups
#(all)(ae-interfaces)
```
set groups AE-SETTINGS interfaces <*> mtu 9196 aggregated-ether-options minimum-links 1 lacp active periodic fast
```

































### igmp-snooping
```
set protocols igmp-snooping vlan all
```

### mld-snooping
```
set protocols mld-snooping vlan all
```

### banner
* DoD
    ```
    set system login announcement "You are accessing a U.S. Government (USG) Information System (IS) that is provided\nfor USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the\nfollowing conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes\nincluding, but not limited to, penetration testing, COMSEC monitoring, network\noperations and defense, personnel misconduct (PM), law enforcement (LE), and\ncounterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine\nmonitoring, interception, and search, and may be disclosed or used for any USG-\nauthorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect\nUSG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI\ninvestigative searching or monitoring of the content of privileged communications, or\nwork product, related to personal representation or services by attorneys,\npsychotherapists, or clergy, and their assistants. Such communications and work product\nare private and confidential. See User Agreement for details."
    ```

### create super-user
```
set system login user kadmin full-name "KTTE Admin" class super-user
set system login user kadmin authentication plain-text-password 
```





















### firewall 
#(ex,qfx)(stig-l2)
```
set firewall family inet filter local_acl term terminal_access from source-address <wht_acc-usr cidr>
set firewall family inet filter local_acl term terminal_access from protocol tcp
set firewall family inet filter local_acl term terminal_access from destination-port ssh
set firewall family inet filter local_acl term terminal_access then log
set firewall family inet filter local_acl term terminal_access then accept
set firewall family inet filter local_acl term terminal_access_denied from protocol tcp
set firewall family inet filter local_acl term terminal_access_denied from destination-port ssh
set firewall family inet filter local_acl term terminal_access_denied from destination-port telnet
set firewall family inet filter local_acl term terminal_access_denied then log
set firewall family inet filter local_acl term terminal_access_denied then reject
set firewall family inet filter local_acl term default-term then accept
set interfaces irb.<mgmt_vlan> family inet filter input local_acl
```

### firewall protect RE
#(srx)(stig-router)
* (srx)
    ```
    set firewall family inet filter PROTECT_RE term ALLOW_OSPF from protocol ospf
    set firewall family inet filter PROTECT_RE term ALLOW_OSPF then count OSPF
    set firewall family inet filter PROTECT_RE term ALLOW_OSPF then accept
    set firewall family inet filter PROTECT_RE term ALLOW_BGP from protocol tcp
    set firewall family inet filter PROTECT_RE term ALLOW_BGP from port bgp
    set firewall family inet filter PROTECT_RE term ALLOW_BGP then count BGP
    set firewall family inet filter PROTECT_RE term ALLOW_BGP then accept
    set firewall family inet filter PROTECT_RE term ALLOW_TCP_MANAGEMENT from destination-address <ip cidr>
    set firewall family inet filter PROTECT_RE term ALLOW_TCP_MANAGEMENT from protocol tcp
    set firewall family inet filter PROTECT_RE term ALLOW_TCP_MANAGEMENT from destination-port ssh
    set firewall family inet filter PROTECT_RE term ALLOW_TCP_MANAGEMENT then count TCP_MANAGEMENT
    set firewall family inet filter PROTECT_RE term ALLOW_TCP_MANAGEMENT then accept
    set firewall family inet filter PROTECT_RE term ALLOW_UDP_MANAGEMENT from destination-address <ip cidr>
    set firewall family inet filter PROTECT_RE term ALLOW_UDP_MANAGEMENT from protocol udp
    set firewall family inet filter PROTECT_RE term ALLOW_UDP_MANAGEMENT from destination-port ntp
    set firewall family inet filter PROTECT_RE term ALLOW_UDP_MANAGEMENT from destination-port snmp
    set firewall family inet filter PROTECT_RE term ALLOW_UDP_MANAGEMENT then count UDP_MANAGEMENT
    set firewall family inet filter PROTECT_RE term ALLOW_UDP_MANAGEMENT then accept
    set firewall family inet filter PROTECT_RE term ALLOW_ICMP from protocol icmp
    set firewall family inet filter PROTECT_RE term ALLOW_ICMP then count ICMP
    set firewall family inet filter PROTECT_RE term ALLOW_ICMP then accept
    set firewall family inet filter PROTECT_RE term ALLOW_DHCP from port dhcp
    set firewall family inet filter PROTECT_RE term ALLOW_DHCP then count DHCP
    set firewall family inet filter PROTECT_RE term ALLOW_DHCP then accept
    set firewall family inet filter PROTECT_RE term DEFAULT_DENY then count DEFAULT
    set firewall family inet filter PROTECT_RE term DEFAULT_DENY then log
    set firewall family inet filter PROTECT_RE term DEFAULT_DENY then reject
    ```
* (ex, qfx, srx)(not production ready)
    ```
    set firewall filter copp_policy term critical from protocol ospf
    set firewall filter copp_policy term critical from protocol pim
    set firewall filter copp_policy term critical from protocol tcp destination-port bgp
    set firewall filter copp_policy term critical from protocol tcp source-port bgp
    set firewall filter copp_policy term critical then policier critical
    ```

### policier
#(qfx,srx)(not production ready)

```
set firewall policer critical filter-specific
set firewall policer critical if-exceeding bandwitch-limit 400000 burst-size-limit 1500
set firewall policer critical then discard

set firewall policer important filter-specific
set firewall policer important if-exceeding bandwitch-limit 152000 burst-size-limit 16000
set firewall policer important then discard

set firewall policer normal filter-specific
set firewall policer normal if-exceeding bandwitch-limit 64000 burst-size-limit 2000
set firewall policer normal then discard

set firewall policer undesirable filter-specific
set firewall policer undesirable if-exceeding bandwitch-limit 32000 burst-size-limit 1500
set firewall policer undesirable then discard

set firewall policer all-other filter-specific
set firewall policer all-other if-exceeding bandwitch-limit 32000 burst-size-limit 1500
set firewall policer all-other then discard
```

### idp 
#(srx)(stig-firewall)
```
set security idp idp-policy srx-policy rulebase-ips rule ddos description "Configured to confirm to STIGs JUSX-IP-000005, JUSX-IP-000006, and JUSX-IP-000007, JUSX-IP-000019"
set security idp idp-policy srx-policy rulebase-ips rule ddos match attacks dynamic-attack-groups ddos-attacks
set security idp idp-policy srx-policy rulebase-ips rule ddos then action no-action
set security idp idp-policy srx-policy rulebase-ips rule ddos then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule datamining description "Configured to confirm to STIG JUSX-IP-000011, JUSX-IP-000013, JUSX-IP-000014, JUSX-IP-000015, JUSX-IP-000016"
set security idp idp-policy srx-policy rulebase-ips rule datamining match attacks dynamic-attack-groups datamining-attacks
set security idp idp-policy srx-policy rulebase-ips rule datamining then action no-action
set security idp idp-policy srx-policy rulebase-ips rule datamining then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule command-injection description "Configured to confirm to STIG JUSX-IP-000012"
set security idp idp-policy srx-policy rulebase-ips rule command-injection match attacks dynamic-attack-groups injection-attacks
set security idp idp-policy srx-policy rulebase-ips rule command-injection then action no-action
set security idp idp-policy srx-policy rulebase-ips rule command-injection then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule rate-based description "Configured to confirm to STIG JUSX-IP-000017, JUSX-IP-000018"
set security idp idp-policy srx-policy rulebase-ips rule rate-based match attacks custom-attacks rate-based
set security idp idp-policy srx-policy rulebase-ips rule rate-based then action no-action
set security idp idp-policy srx-policy rulebase-ips rule rate-based then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule critical-attacks description "Configured to confirm to STIG JUSX-IP-000024"
set security idp idp-policy srx-policy rulebase-ips rule critical-attacks match attacks dynamic-attack-groups critical-recommended
set security idp idp-policy srx-policy rulebase-ips rule critical-attacks then action no-action
set security idp idp-policy srx-policy rulebase-ips rule critical-attacks then notification log-attacks alert
set security idp idp-policy srx-policy rulebase-ips rule major-attacks match attacks dynamic-attack-groups major-recommended
set security idp idp-policy srx-policy rulebase-ips rule major-attacks then action no-action
set security idp idp-policy srx-policy rulebase-ips rule major-attacks then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule minor-attacks match attacks dynamic-attack-groups minor-recommended
set security idp idp-policy srx-policy rulebase-ips rule minor-attacks then action no-action
set security idp idp-policy srx-policy rulebase-ips rule minor-attacks then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule warning-attacks match attacks dynamic-attack-groups warning-recommended
set security idp idp-policy srx-policy rulebase-ips rule warning-attacks then action no-action
set security idp idp-policy srx-policy rulebase-ips rule warning-attacks then notification log-attacks
set security idp idp-policy srx-policy rulebase-ips rule malicious-activity description "Configured to confirm to STIG JUSX-IP-000027"
set security idp idp-policy srx-policy rulebase-ips rule malicious-activity match attacks dynamic-attack-groups malicious-activity
set security idp idp-policy srx-policy rulebase-ips rule malicious-activity then action no-action
set security idp idp-policy srx-policy rulebase-ips rule malicious-activity then notification log-attacks alert
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning description "Standard exemptions due to known false positives or resource limitations"
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks TCP:C2S:AMBIG:C2S-SYN-DATA
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks SMB:ERROR:MAL-SMB2-MSG
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:STC:HIDDEN-IFRAME-2
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:STC:IMG:PNG-CHUNK-OF-1
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:INVALID:CONTENT-TYPE-MIS
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks DNS:MS-FOREFRONT-RCE
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks SSL:FACEBOOK-FIZZ-TLS13-IO-DOS
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:OVERFLOW:CHUNK-OVERFLOW
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks TCP:ERROR:FLOW-MEMORY-EXCEEDED
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks TCP:ERROR:REASS-MEMORY-OVERFLOW
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks VOIP:SIP:HAMMER
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:INVALID:UNEXPECTCHAR
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks SMB:ERROR:GRIND
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:STC:IE:CVE-2018-0978-RCE
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks SSL:OVERFLOW:KEY-ARG-NO-ENTROPY
set security idp idp-policy srx-policy rulebase-exempt rule initial-tuning match attacks predefined-attacks HTTP:STC:DL:CVE-2018-8413-RCE
set security idp default-policy srx-policy
set security idp custom-attack rate-based severity info
set security idp custom-attack rate-based time-binding count 2
set security idp custom-attack rate-based time-binding scope peer
set security idp custom-attack rate-based attack-type anomaly service TCP
set security idp custom-attack rate-based attack-type anomaly test OPTIONS_UNSUPPORTED
set security idp custom-attack rate-based attack-type anomaly direction any
set security idp custom-attack rate-based attack-type anomaly shellcode sparc
set security idp dynamic-attack-group datamining-attacks filters recommended
set security idp dynamic-attack-group datamining-attacks filters category values DB
set security idp dynamic-attack-group ddos-attacks filters recommended
set security idp dynamic-attack-group ddos-attacks filters category values DDOS
set security idp dynamic-attack-group ddos-attacks filters category values DOS
set security idp dynamic-attack-group injection-attacks filters recommended
set security idp dynamic-attack-group injection-attacks filters vulnerability-type values cmd-inj
set security idp dynamic-attack-group critical-recommended filters severity values critical
set security idp dynamic-attack-group critical-recommended filters recommended
set security idp dynamic-attack-group major-recommended filters severity values major
set security idp dynamic-attack-group major-recommended filters recommended
set security idp dynamic-attack-group minor-recommended filters severity values minor
set security idp dynamic-attack-group minor-recommended filters recommended
set security idp dynamic-attack-group warning-recommended filters severity values warning
set security idp dynamic-attack-group warning-recommended filters recommended
set security idp dynamic-attack-group malicious-activity filters recommended
set security idp dynamic-attack-group malicious-activity filters category values SHELLCODE
set security idp dynamic-attack-group malicious-activity filters category values VIRUS
set security idp dynamic-attack-group malicious-activity filters category values WORM
set security idp dynamic-attack-group malicious-activity filters category values SPYWARE
set security idp dynamic-attack-group malicious-activity filters category values TROJAN
set security idp security-package automatic start-time "2021-9-1.11:00:00 +0000"
set security idp security-package automatic interval 24
set security idp security-package automatic enable
```

### ids
#(srx)(stig-firewall)
```
set security screen ids-option untrust-screen icmp ip-sweep threshold 1000
set security screen ids-option untrust-screen icmp ping-death
set security screen ids-option untrust-screen ip bad-option
set security screen ids-option untrust-screen ip record-route-option
set security screen ids-option untrust-screen ip timestamp-option
set security screen ids-option untrust-screen ip security-option
set security screen ids-option untrust-screen ip stream-option
set security screen ids-option untrust-screen ip spoofing
set security screen ids-option untrust-screen ip source-route-option
set security screen ids-option untrust-screen ip unknown-protocol
set security screen ids-option untrust-screen ip tear-drop
set security screen ids-option untrust-screen ip ipv6-extension-header hop-by-hop-header jumbo-payload-option
set security screen ids-option untrust-screen ip ipv6-extension-header hop-by-hop-header router-alert-option
set security screen ids-option untrust-screen ip ipv6-extension-header hop-by-hop-header quick-start-option
set security screen ids-option untrust-screen ip ipv6-extension-header routing-header
set security screen ids-option untrust-screen ip ipv6-extension-header fragment-header
set security screen ids-option untrust-screen ip ipv6-extension-header no-next-header
set security screen ids-option untrust-screen ip ipv6-extension-header shim6-header
set security screen ids-option untrust-screen ip ipv6-extension-header mobility-header
set security screen ids-option untrust-screen ip ipv6-malformed-header
set security screen ids-option untrust-screen tcp syn-fin
set security screen ids-option untrust-screen tcp fin-no-ack
set security screen ids-option untrust-screen tcp tcp-no-flag
set security screen ids-option untrust-screen tcp syn-frag
set security screen ids-option untrust-screen tcp port-scan threshold 1000
set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1000
set security screen ids-option untrust-screen tcp syn-flood attack-threshold 1100
set security screen ids-option untrust-screen tcp syn-flood source-threshold 100
set security screen ids-option untrust-screen tcp syn-flood destination-threshold 2048
set security screen ids-option untrust-screen tcp syn-flood timeout 20
set security screen ids-option untrust-screen tcp land
set security screen ids-option untrust-screen udp flood threshold 5000
set security screen ids-option untrust-screen udp udp-sweep threshold 1000
```

### universal threat manager
#(srx)(stig-firewall)
```
set security utm custom-objects mime-pattern shockwave_flash value video/x-shockwave-flash
set security utm custom-objects mime-pattern bypass-mime value text/css
set security utm custom-objects mime-pattern bypass-mime value audio/
set security utm custom-objects mime-pattern bypass-mime value video/
set security utm custom-objects mime-pattern bypass-mime value image/
set security utm custom-objects filename-extension vb_javascript value vbs
set security utm custom-objects filename-extension vb_javascript value js
set security utm default-configuration anti-virus mime-whitelist list bypass-mime
set security utm default-configuration anti-virus type sophos-engine
set security utm default-configuration anti-virus fallback-options default permit
set security utm default-configuration anti-virus sophos-engine pattern-update url https://update.juniper-updates.net/SAV/
set security utm default-configuration anti-virus sophos-engine pattern-update interval 1440
set security utm default-configuration content-filtering block-extension vb_javascript
set security utm default-configuration content-filtering block-mime list shockwave_flash
set security utm default-configuration content-filtering block-content-type activex
set security utm default-configuration content-filtering block-content-type java-applet
set security utm feature-profile anti-virus profile av-profile fallback-options default permit
set security utm feature-profile anti-virus profile av-profile mime-whitelist list bypass-mime
set security utm feature-profile content-filtering profile content-filtering-profile block-extension vb_javascript
set security utm feature-profile content-filtering profile content-filtering-profile block-mime list shockwave_flash
set security utm feature-profile content-filtering profile content-filtering-profile block-content-type activex
set security utm feature-profile content-filtering profile content-filtering-profile block-content-type java-applet
set security utm utm-policy utm-policy anti-virus http-profile av-profile
set security utm utm-policy utm-policy anti-virus ftp upload-profile av-profile
set security utm utm-policy utm-policy anti-virus ftp download-profile av-profile
set security utm utm-policy utm-policy anti-virus smtp-profile av-profile
set security utm utm-policy utm-policy anti-virus pop3-profile av-profile
set security utm utm-policy utm-policy anti-virus imap-profile av-profile
deactivate security utm utm-policy utm-policy anti-virus
set security utm utm-policy utm-policy content-filtering http-profile content-filtering-profile
```

### security zones
#(srx)(stig-firewall)
```
set security zones security-zone <zone> interfaces <interface>
##as needed
set security zones security-zone <zone> host-inbound-traffic system-services ping
set security zones security-zone <zone> host-inbound-traffic system-services dhcp
set security zones security-zone <zone> host-inbound-traffic system-services ssh
```

### security policies
#(srx)(stig-firewall)
```
set security policies from-zone <zone> to-zone <zone> poicy <policy name> match source address <ip cidr or any>
set security policies from-zone <zone> to-zone <zone> poicy <policy name> match desination address <ip cidr or any>
set security policies from-zone <zone> to-zone <zone> poicy <policy name> match application <application name or any>
set security policies from-zone <zone> to-zone <zone> poicy <policy name> then <action>
```

### security policies - default deny
#(srx)(stig-firewall)(required at the end of each ruleset)
```
set security policies from-zone <zone> to-zone <zone> policy default-deny match source-address any
set security policies from-zone <zone> to-zone <zone> policy default-deny match destination-address any
set security policies from-zone <zone> to-zone <zone> policy default-deny match application any
set security policies from-zone <zone> to-zone <zone> policy default-deny then deny
```

### security policies - applications
#(srx)(stig-firewall)
```
set applications application <name> protocol <tcp/udp>
set applications application <name> destination-port <port>
set applications application <name> inactivity-timeout <timeout (900)>
```

### security policies - application set
#(srx)
```
set applications application-set <name> application <application name>
```

### ipsec fips compliant
#(srx)(stig-firewall)
```
set security ipsec internal security-association manual encryption algorithm aes-128-cbc
set security ipsec internal security-association manual encryption ike-ha-link-encryption enable
set security ipsec internal security-association manual encryption key ascii-text <key>
```

### address book
#(srx)
* global
    ```
    set security address-book global address <name> <host cidr>
    set security address-book global address-set <name> address <address-book name>
    ```
* per security zone
    ```
    set security zones security-zone <zone name> address-book <name> <host cidr>
    set security zones security-zone <zone name> address-set <name> address <address-book name>
    ```


##PORT RELATED TASKS

### set if virtual-chassis
```
set virtual-chassis preprovisioned
set virtual-chassis member 0 serial-number <serial> role routing-engine
set virtual-chassis member 1 serial-number <serial> role routing-engine
set virtual-chassis member 2 serial-number <serial> role line-card
set system commit synchronize
set virtual-chassis no-split-detection
```

### set management interface
```
set interfaces irb unit <mgmt-vlan ##99> family inet address <cidr>
set vlan <vlan name> vlan-id <vlan id ##99> l3-interface irb.<vlan id  ##99>
```

### dhcp snooping
```
set vlans <user vlan name> forwarding-options dhcp-security
set vlans <user vlan name> forwarding-options dhcp-security ip-source-guard
set vlans <user vlan name> forwarding-options dhcp-security ip6-source-guard
set vlans <user vlan name> forwarding-options dhcp-security arp-inspection
##manually add host to snooping table
set vlans <user vlan name> forwarding-options dhcp-security group <group name> interface <interface> static-ip <ip address> mac <mac address>
set vlans <user vlan name> forwarding-options dhcp-security group <group name> interface <interface> static-ipv6 <ip address> mac <mac address>
##disable dhcp snooping
set vlans <user vlan name> forwarding-options dhcp-security no-dhcp-snooping
set vlans <user vlan name> forwarding-options dhcp-security no-dhcpv6-snooping
```

### create lag interface
```
set interface ae0 apply-groups AE-SETTINGS
set chassis aggregated-devices ethernet device-count 1
wildcard range delete interfaces et-0/1/[0-1]
wildcard range delete protocols rstp interface et-0/1/[0-1]  
wildcard range set interfaces et-0/1/[0-1] ether-options 802.3ad ae0
set interfaces ae0 description ae0 -> <remote building>-<ae interface>
set interfaces ae0 aggregated-ether-optins lacp active
set interfaces ae0 unit 0 family ethernet-switching inteface-mode trunk vlan members [ ##02 ##95 ##99 ]
set interfaces ae0 native-vlan-id 998
```

### interconnect between qfx5100 and ex4300 qsfp ports does not work with auto-negotiation enabled on the ex4300
```
set interface <iface> ether-options no-auto-negotiation
```

### voip
```
set protocols lldp-med interface <iface>
set switch options voip interface <iface>.0 vlan <voip vlan>
```

### port ranges - delete configurations
```
wildcard range delete interface ge-0/0/[0-47]
wildcard range delete interface et-0/1/[0-3]
wildcard range delete interface xe-0/1/[2-3]
wildcard range delete interface ge-0/2/[0-3]
wildcard range delete interface et-0/2/[0-3]

delete vlans default
```

### port ranges - vlans (blackhole)
```
wildcard range set interface ge-0/0/[0-47] unit 0 family ethernet-switching vlan members blackhole
wildcard range set interface ge-0/0/[0-47] description disabled
wildcard range set interface ge-0/0/[0-47] disable

wildcard range set interface xe-0/1/[0-3] unit 0 family ethernet-switching vlan members blackhole
wildcard range set interface xe-0/1/[0-3] description disabled
wildcard range set interface xe-0/1/[0-3] disable

wildcard range set interface et-0/1/[2-3] unit 0 family ethernet-switching vlan members blackhole
wildcard range set interface et-0/1/[2-3] description disabled
wildcard range set interface et-0/1/[2-3] disable

wildcard range set interface ge-0/2/[0-3] unit 0 family ethernet-switching vlan members blackhole
wildcard range set interface ge-0/2/[0-3] description disabled
wildcard range set interface ge-0/2/[0-3] disable

wildcard range set interface xe-0/2/[0-3] unit 0 family ethernet-switching vlan members blackhole
wildcard range set interface xe-0/2/[0-3] description disabled
wildcard range set interface xe-0/2/[0-3] disable
```

### port security (ex)(stig-l2)
```
wildcard range set switch-options interface ge-0/0/[0-47] interface-mac-limit 1
wildcard range set switch-options interface ge-0/0/[0-47] persistent-learning
wildcard range set switch-options interface ge-0/0/[0-47] interface-mac-limit packet-action shutdown
```

### spanning tree (ex)(stig-l2)
```
wildcard range set protocols rstp interface ge-0/0/[<access port range>]
wildcard range set protocols layer2-control bpdu-block interface ge-0/0/[<access port range>]
set protocols rstp bpdu-block-on-edge
wildcard range set protocols rstp interface ge-0/0/[<access port range>] no-root-port
wildcard range set protocols rstp interface ge-0/0/[<access port range> edge
```

### uufb (ex)(stig-l2)
```
set switch-options unknown-unicast-forwarding vlan <vlan with access ports> interface <interface to forward to>
```

### storm control (ex)(stig-l2)
```
set forwarding-options storm-control-profiles default all bandwidth-percentage 80
set interfaces <access interface> unit 0 family ethernet-switching storm-control default
```

### rsa keyfile login (do not use)
```
set system login user <username> class <class> authentication load-key-file <path to pub keyfile>
##keyfile can be local fs or scp "scp://<user>@<remote ip>:<path>"
```

### source nat
```
set security nat source rule-set <rule set name> from zone <from internal zone>
set security nat source rule-set <rule set name> to zone <untrust zone>

set security nat source rule-set <rule set name> rule <rule name> match source-address <internal cidr>
set security nat source rule-set <rule set name> rule <rule name> match destination-address 0.0.0.0/0
set security nat source rule-set <rule set name> rule <rule name> then source-nat interface
```
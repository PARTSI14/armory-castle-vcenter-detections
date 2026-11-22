# Hunting checklist & hardening: Armory Castle vSphere campaign

> Use this when you **cannot rely on detections alone**. vCenter, ESXi and most Linux appliances run no EDR, and Mandiant notes the actor deletes `.bash_history`. Hunt across what you forwarded to the SIEM, and collect live artefacts before you reboot anything.

## 0. First 24 hours if you run vCenter

- [ ] Patch vCenter for **CVE-2026-123890** (VMSA-2026-0009). Fixed in 9.1.1.0200, 9.0.2.0200 and 8.0 U3m. Broadcom lists **no workaround**.
- [ ] Patch BeyondTrust Remote Support to **BT26-05** (CVE-2026-102764).
- [ ] Assume compromise if either was exposed and unpatched before 19 Nov 2026. **Patching does not remove** SSO accounts, SSH keys or forged-SAML capability that were already created.

## 1. Hunting checklist

### BeyondTrust / Linux appliances
- [ ] JSP files in web roots that you did not deploy (`ActiveSer.jsp`, `u.jsp`, or any recent `.jsp`)
- [ ] Files in `/tmp`: `123`, `sss`, `dbr`, `rar`, `123.rar`, `123.key`, `gdb_file`
- [ ] `/usr/bin/vmtoolscs` and a systemd unit that starts it
- [ ] SUID bit on `/bin/env`: `find / -perm -4000 -newer /etc/hostname 2>/dev/null`
- [ ] Listening ports **53** or **33992** on hosts that are not DNS servers: `ss -lntp`
- [ ] Outbound connections from servers to `slack.com/api/*`

### vCenter
- [ ] **Every** account in `vsphere.local` created recently. Pay special attention to `sps-*@vsphere.local`, but BONESAW lets the operator choose any name.
- [ ] New machine accounts in vmdir, and new **Global Administrator** permissions on the root folder
- [ ] VAMI access logs: `PUT /rest/appliance/access/ssh` (SSH turned on) followed soon after by SSH being turned off
- [ ] SSH logins to the VCSA that do not match a change ticket
- [ ] Any process other than `vmdird` touching `/storage/db/vmware-vmdir/data.mdb`
- [ ] SAML logins (`/ui/saml/websso/sso`) for admin users at unusual times or from unusual hosts. Golden SAML **bypasses MFA**, so MFA logs will look clean.

### ESXi
- [ ] `/etc/ssh/keys-root/authorized_keys`: compare against your known keys
- [ ] `/var/log/auth.log`: root and `vpxuser` SSH sessions from appliance IPs
- [ ] `/var/log/shell.log`: `vmfs_browser`, `vmfs-pydist`, `tar`, `scp` into `/vmfs/volumes/*/.a`
- [ ] Hidden directories on datastores: `find /vmfs/volumes/ -maxdepth 2 -name ".*" -type d`

### Network
- [ ] SSH servers announcing `SSH-2.0-pulsesecure_23345` (Zeek `ssh.log`, field `server`)
- [ ] Large scp/SSH transfers from ESXi to Linux appliances
- [ ] TCP 2012 (vmdir) connections to vCenter from anything that is not a vCenter/PSC node

## 2. If you find it: response priorities

Golden SAML means the attacker can log in as **anyone** without a password until the signing key changes. Order matters:

1. Isolate the BeyondTrust and Linux appliances. Keep memory and disks for forensics.
2. Remove attacker accounts (SSO admins, machine accounts, `sps-*`), SSH keys and permissions.
3. **Replace the vCenter STS signing certificate**, so forged SAML tokens stop working.
4. Rotate: `administrator@vsphere.local`, ESXi `root` passwords, the `vpxuser` relationship, and PostgreSQL credentials.
5. **Domain controllers were read from disk** (NTDS.dit). Treat **all** AD passwords as stolen: double `krbtgt` reset, and reset privileged and service accounts.
6. Rebuild appliances from known-good images where integrity is uncertain.

## 3. Hardening (from Mandiant's guidance)

| Control | Why it matters here |
|---|---|
| Default-deny **inbound** on VCSA (443, 2012, 22, 5480) with allow-lists of admin IPs | The exploit used TCP 2012 from an internal appliance |
| **Egress DROP** on VCSA and ESXi | Blocks scp exfiltration and Slack C2 |
| iptables rules enforced at the Photon OS level, not only the VAMI GUI | Stolen VAMI credentials cannot switch them off |
| SSH and BASH shell **disabled by default**, alert on enablement | The actor turned SSH on through VAMI, then off |
| Remote syslog of shell commands and dropped packets | VCSA does not forward these by default |
| ESXi 8.0+: `esxcli system account set -i vpxuser -s false` | Stops a compromised vCenter from changing ESXi root passwords |
| ESXi `Syslog.global.auditRecord.storageEnable = TRUE` + remote forwarding | Audit records are off by default |
| Privileged Access Workstations for vSphere admin | Limits where SSO admin sessions come from |
| auditd watch: `-w /storage/db/vmware-vmdir/data.mdb -p r -k vmdir_db` | Catches the data.mdb theft even without process logging |

> Note: Mandiant's text gives TCP **2012** for the exploit, but one hardening table says "TCP 2010" for vmdird. Check your vCenter version's port list before you write firewall rules.

Sources: Mandiant/GTIG, *ARMORY CASTLE exploits vSphere* (19 Nov 2026); Mandiant, *Defending vSphere from UNC3944*; Mandiant, *vSphere and BRICKSTORM Malware: A Defender's Guide*.

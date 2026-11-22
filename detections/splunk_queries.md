# Splunk queries (auto-generated from the Sigma rules)

Converted with pySigma + pysigma-backend-splunk (no field-mapping pipeline: field names are kept as in the Sigma rules).
Add your own `index=` / `sourcetype=` prefix and map the fields to your data, for example Linux auditd or Sysmon for Linux (`Image`, `CommandLine`), vCenter/VAMI access logs (`cs-method`, `cs-uri-stem`), proxy logs (`cs-host`, `c-uri`) and Zeek `ssh.log` (`server`).

## ESXi - SSH Key Added, Hidden VMFS Staging or VMFS Browser Tool

Source: `sigma/esxi_shell_ssh_key_or_vmfs_staging.yml`

```spl
"authorized_keys" OR "vmfs_browser" OR "vmfs-pydist" OR ("/vmfs/volumes/" "/.a")
```

## Linux Appliance - Execution of Armory Castle Tool Paths (BONESAW, SAWSNAKE, BEARBONES, LAZYBONES)

Source: `sigma/linux_armory_castle_tool_paths.yml`

```spl
Image IN ("/tmp/123", "/tmp/sss", "/tmp/dbr", "/usr/bin/vmtoolscs")
```

## Linux Appliance - Base64 Decoded Into /tmp

Source: `sigma/linux_base64_decode_to_tmp.yml`

```spl
(CommandLine IN ("*base64 -d*", "*base64 --decode*")) CommandLine="*/tmp/*"
```

## Linux Appliance - curl Download to /tmp or Password-Protected RAR Extraction

Source: `sigma/linux_curl_to_tmp_or_rar_extract.yml`

```spl
(Image="*/curl" (CommandLine IN ("* -o /tmp/*", "* --output /tmp/*"))) OR ((Image IN ("*/rar", "*/unrar")) CommandLine="* x *" CommandLine="* -p*")
```

## Linux Appliance - gdb Command File Execution or SUID Bit Set on a Shell-Capable Binary

Source: `sigma/linux_gdb_command_file_or_suid_set.yml`

```spl
(Image="*/gdb" (CommandLine IN ("*--command=*", "*--batch*"))) OR (Image="*/chmod" (CommandLine IN ("*u+s*", "*4755*", "*+s *")) (CommandLine IN ("*/bin/env*", "*/bin/bash*", "*/bin/sh*", "*/usr/bin/find*", "*/usr/bin/python*")))
```

## Linux Appliance - nmap Scan of VMware Management Ports

Source: `sigma/linux_nmap_vmware_management_ports.yml`

```spl
Image="*/nmap" (CommandLine IN ("*2012*", "*5480*", "*9080*"))
```

## Linux Appliance - SSH Server Binary Started From /tmp

Source: `sigma/linux_ssh_server_started_from_tmp.yml`

```spl
(Image IN ("/tmp/*", "/var/tmp/*", "/dev/shm/*")) CommandLine="* -R*" CommandLine="* -p *"
```

## Network - Server Calling Slack API Used for C2 (conversations.history / external file upload)

Source: `sigma/proxy_slack_api_from_server.yml`

```spl
"cs-host"="*slack.com" ("c-uri" IN ("*/api/conversations.history*", "*/api/files.getUploadURLExternal*", "*/api/files.completeUploadExternal*"))
```

## vCenter - Local SSO Account Matching Armory Castle Naming (sps-*@vsphere.local)

Source: `sigma/vcenter_sso_admin_account_sps_pattern.yml`

```spl
"@vsphere.local" "sps-"
```

## vCenter - SSH Enabled Through the VAMI REST API

Source: `sigma/vcenter_vami_ssh_enabled_via_api.yml`

```spl
"cs-method"="PUT" "cs-uri-stem"="*/rest/appliance/access/ssh*"
```

## vCenter - VMware Directory Database (data.mdb) Accessed by a Process Other Than vmdird

Source: `sigma/vcenter_vmdir_database_access.yml`

```spl
CommandLine="*/storage/db/vmware-vmdir/data.mdb*" NOT Image="*/vmdird"
```

## Network - SSH Server Banner Spoofing Pulse Secure (BEARBONES)

Source: `sigma/zeek_ssh_pulsesecure_banner.yml`

```spl
server="*pulsesecure_23345*"
```

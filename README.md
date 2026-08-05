# IAM / Active Directory Case Study

## What this demonstrates

End-to-end Active Directory identity administration — domain provisioning, OU structure, bulk user creation, group-based delegation, and a least-privilege access control model — implemented on a self-hosted Samba4 domain controller, with a physically separate Windows 10 machine joined to the same network as a real domain client.

## Environment

- **Domain controller:** Samba4 on Ubuntu Server, running as a VM on the MacBook Air (dual-homed — one adapter bridged to the real LAN, one on the isolated HomeLab network used by the other lab VMs)
- **Domain:** `LAB.LOCAL`
- **Domain client:** Windows 10 Pro, bare-metal on a Mac Mini, domain-joined and confirmed via `CsPartOfDomain: True`
- **Why Samba4 instead of Windows Server:** a standard x86 Windows Server ISO runs painfully slow through emulation on Apple Silicon. Samba4 implements real AD Domain Services natively, at full speed, with the same OU/group/delegation concepts — see the note on the bare-metal Windows Server attempt below for the full story of why this was the right call for this hardware.

## Process

### 1. Provision the domain

```bash
sudo apt install -y samba krb5-config winbind smbclient samba-ad-provision samba-dsdb-modules samba-vfs-modules acl krb5-user
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
sudo samba-tool domain provision --use-rfc2307 --interactive
```

Provisioning creates the AD database, Kerberos KDC configuration, and DNS zone from scratch. Realm `LAB.LOCAL`, domain `LAB`, role `dc`, DNS backend `SAMBA_INTERNAL`.

### 2. Switch from file-server mode to full domain controller mode

Ubuntu's base `samba` package only provides the file-server role (smbd/nmbd/winbind). The AD DC role is a separate service:

```bash
sudo apt install -y samba-ad-dc
sudo systemctl stop smbd nmbd winbind
sudo systemctl disable smbd nmbd winbind
sudo systemctl unmask samba-ad-dc
sudo systemctl enable --now samba-ad-dc
```

### 3. Point the machine's own DNS resolution at itself

Samba's internal DNS server needs to actually be queried for domain lookups to resolve. `systemd-resolved` holds port 53 by default and needs to be disabled first:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
echo "search lab.local" | sudo tee -a /etc/resolv.conf
sudo systemctl restart samba-ad-dc
```

### 4. Verify the domain is genuinely functional

```bash
host -t SRV _ldap._tcp.lab.local
kinit administrator@LAB.LOCAL
klist
```

Confirmed: real SRV record for the LDAP service, valid Kerberos ticket issued for the Administrator principal.

### 5. Build the OU structure and provision users

```bash
sudo samba-tool ou create "OU=IT,DC=lab,DC=local"

for u in jsmith agarcia mchen; do
  sudo samba-tool user create "$u" "TempPass123!" --given-name="$u"
  sudo samba-tool user move "$u" "OU=IT,DC=lab,DC=local"
done
```

### 6. Create a helpdesk group and delegate password-reset rights — scoped, not domain-wide

```bash
sudo samba-tool group add Helpdesk-IT
sudo samba-tool group addmembers Helpdesk-IT jsmith
sudo samba-tool user setexpiry jsmith --days=0
```

Delegation itself is applied as a direct access control entry on the OU, using AD's standard "Reset Password" extended-right GUID, scoped to the Helpdesk-IT group's SID:

```bash
sudo samba-tool dsacl set --objectdn="OU=IT,DC=lab,DC=local" \
  --sddl="(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;S-1-5-21-714864701-590618205-2929429102-1106)"
```

Verified by reading the ACE directly back off the object:

```bash
sudo samba-tool dsacl get --objectdn="OU=IT,DC=lab,DC=local" | grep -o "(OA;[^)]*1106)"
```

## Key finding

Helpdesk-IT's members can reset passwords for users inside the IT OU — nothing more. They can't create accounts, can't touch other OUs, can't modify group membership outside what's explicitly granted. This is the actual access-control model real IT support tiers are built on: give the helpdesk exactly enough access to do the job, not domain admin by default. The verification step above doesn't just confirm the delegation *appears* to work through a GUI — it reads the raw access control entry directly off the object, which is the same mechanism Windows AD Domain Services uses internally.

## Files in this repo

- `user_list.txt` — output of `samba-tool user list`, showing the three provisioned users alongside built-in accounts
- `helpdesk_members.txt` — confirms jsmith's membership in Helpdesk-IT
- `delegation_ace.txt` — the raw access control entry proving the scoped delegation is in place
- `users.csv` — input data for scripted bulk provisioning (see addendum below)
- `provision_users.py` — the CSV-driven provisioning script
- `screenshots/` — terminal output captures (see below)

## Screenshots

![Domain controller status](screenshots/domain-controller-status.png)
![Kerberos authentication confirmed](screenshots/kerberos-confirmation.png)
![Password-reset delegation verified](screenshots/delegation-proof.png)
![CSV-driven provisioning](screenshots/csv-provisioning.png)
![Domain password policy applied](screenshots/password-policy-set.png)
![Domain password policy verified](screenshots/password-policy-verified.png)

## Infrastructure note: the Windows 10 domain client

A physical Windows 10 Pro machine (a repurposed 2014 Mac Mini, running Windows via Boot Camp) is domain-joined to this same domain — confirmed via `Get-ComputerInfo` returning `CsPartOfDomain: True`, `CsDomain: lab.local` — demonstrating the client side of this setup, not just the server console. Getting Windows running on that hardware at all was its own significant undertaking, documented in full in this portfolio's main lab playbook, including an abandoned bare-metal Windows *Server* attempt and the eventual working Windows 10 + Boot Camp Assistant path. That write-up is kept separate from this repo since it's really its own story about unsupported-hardware troubleshooting — but it's the reason this project's domain-controller work happened on Samba4 rather than Windows Server in the first place.

## What I'd do differently in production

- Use Group Policy (via Samba4's limited GPO support, or a real Windows Server DC in production) to enforce the same least-privilege posture at the client level, not just the directory level.

---

## Addendum: CSV-Driven Provisioning + Domain Password Policy

### What this adds

The original build hardcoded three usernames directly into a shell loop. This upgrade replaces that with data-driven provisioning from a CSV file — directly reusable Python skill from the `log-ioc-parser` project — plus a real, verified domain-wide password policy.

### The provisioning script

```python
import csv
import subprocess
import sys

with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        subprocess.run([
            "sudo", "samba-tool", "user", "create",
            row["username"], "TempPass123!",
            f"--given-name={row['given_name']}"
        ], check=True)
        subprocess.run([
            "sudo", "samba-tool", "user", "move",
            row["username"], row["ou"]
        ], check=True)
        print(f"Provisioned {row['username']} into {row['ou']}")
```
`csv.DictReader` reads each row keyed by the CSV's header row, so `row["username"]` works regardless of column order. `subprocess.run([...], check=True)` passes the command as a list of separate arguments rather than one concatenated string — the safer approach, since it avoids the shell needing to parse anything, sidestepping a class of injection risk that string-concatenated commands are vulnerable to. `check=True` makes the script stop immediately on any failed `samba-tool` call rather than silently continuing past a broken provisioning step.

### The domain password policy

```bash
sudo samba-tool domain passwordsettings set --complexity=on --min-pwd-length=12 --history-length=5
```
Verified independently, not just trusted from the `set` command's own success message:
```bash
sudo samba-tool domain passwordsettings show
```
Confirmed active: complexity on, 12-character minimum, 5-password history.

### Key finding

Both pieces replace something that only worked at lab-demo scale with something that scales to a real environment: provisioning driven by external data instead of names baked into the script, and a directory-wide policy actually enforced by the domain controller rather than left at defaults. The verification step for the password policy matters for the same reason delegation was verified by reading the raw ACE back in the original project — a settings command reporting success and a setting actually being active are two different claims, and only the second one is real evidence.

---

## Addendum: Layered Defense — AD Account Lockout + SIEM Correlation

### What this adds

A demonstration that this domain's account lockout policy and the Wazuh SIEM built in Project 2 respond to the same attack independently — two separate control layers, neither aware of nor dependent on the other, rather than a single point of detection dressed up as two.

### Prerequisite: domain-joining Ubuntu-target

Testing this required a real SSH domain login against Ubuntu-target, which wasn't previously domain-integrated — only the Windows 10 client (see infrastructure note above) had ever authenticated against this domain before. Domain-joining Ubuntu-target (winbind, NSS, PAM) was completed first, entirely within the isolated HomeLab segment Samba4's second interface already shares — no change to this lab's network isolation boundary.

That process surfaced a real, previously undetected bug: the original provisioning above (Step 6) ran `samba-tool user setexpiry jsmith --days=0`, intending "never expires" — but `--days=0` actually expires the account at the end of the day it's run, not never. `jsmith`'s account had been silently expired since its creation on July 23, undetected because nothing before this point had attempted a real password-based domain login. Fixed with the correct flag:

```bash
sudo samba-tool user setexpiry jsmith --noexpiry
```

### Steps

```bash
# Domain-wide account lockout policy (Samba4)
sudo samba-tool domain passwordsettings set --account-lockout-threshold=5 --account-lockout-duration=15 --reset-account-lockout-after=15

# Attack (Kali, targeting the now domain-integrated Ubuntu-target)
hydra -t 4 -l jsmith -P /usr/share/wordlists/rockyou.txt ssh://192.168.81.130
```

### Layer 1: directory service response

```
$ sudo samba-tool user show jsmith | grep -i lock
lockoutTime: 134303420349577910
```

A non-zero value confirms the domain genuinely locked the account after 5 failed attempts.

### Layer 2: SIEM response

Wazuh's rule 100010 (built in Project 2) fired independently — 24 times across the attack window — reading `auth.log`/`journald` on Ubuntu-target directly, with no dependency on the AD lockout state:

```json
{"rule":{"id":"100010","description":"Multiple SSH authentication failures from same source - possible brute force (T1110)","mitre":{"id":["T1110"]}},"data":{"srcip":"192.168.81.128","dstuser":"jsmith"}}
```

### Key finding

Two unrelated control planes — a directory-service lockout policy and a log-based SIEM detection rule — both independently caught the identical attack. Neither depends on or triggers the other; each would still catch this attack even if the other were disabled entirely. That's the actual substance of "defense in depth," not just a label applied after the fact.

---

## Addendum: Backup & Disaster Recovery Verification

### What this adds

Backup *verification*, not just backup creation — most "I have backups" claims are never actually tested against a real restore. This project simulates a genuine failure and proves recovery with a diff, not just a service that comes back up.

### A recurring infrastructure issue, fixed properly this time

Before backup testing could even start, Samba4 hit the same IPv6-related KDC crash documented earlier in this lab's build (`kdc_add_socket: Failed to bind to <ipv6-address> UDP`) — a third occurrence, despite a prior fix. Root cause this time: the earlier fix only disabled DHCPv6 (`dhcp6: false`), but a separate mechanism — IPv6 Router Advertisements (`accept-ra`) — can independently assign a global IPv6 address via SLAAC regardless of DHCPv6 settings. Disabling both at the netplan level is what actually made the fix durable:

```bash
sudo tee /etc/netplan/00-installer-config.yaml > /dev/null << 'EOF'
network:
  ethernets:
    enp26s0:
      accept-ra: false
      dhcp4: true
      dhcp6: false
    enp2s0:
      accept-ra: false
      dhcp4: true
      dhcp6: false
      match:
        macaddress: 00:0c:29:6f:e9:30
      set-name: enp2s0
  version: 2
EOF
sudo netplan apply
```

### Why `samba-tool domain backup online`/`restore` was abandoned

The built-in Samba backup/restore workflow was attempted first, per the original plan, and hit three separate real issues in sequence: a CLDAP self-discovery failure during backup (resolved by targeting the DC's actual IP instead of `localhost`); an upstream-acknowledged Samba limitation preventing a restore from using the same DC name already present in the backup snapshot (confirmed via Samba's own mailing list — the restore process adds the "new" DC before removing old entries, and can't currently handle a name collision with itself); and finally an unresolved internal `"Samba failed to prime database, error code 22"` failure with no public documentation matching this exact scenario. Rather than keep chasing an increasingly obscure, apparently fragile code path, the approach was switched to a simpler, well-established method: a plain file-level backup of the AD database directory. This is itself a real, defensible engineering call — recognizing when a "supported" tool isn't reliable enough to depend on, and falling back to a more transparent method rather than staying wedded to one command.

### Steps

```bash
# Backup: stop briefly for a consistent copy, archive, restart
sudo systemctl stop samba-ad-dc
sudo tar -czvf ~/samba-private-backup.tar.gz -C /var/lib/samba private
sudo systemctl start samba-ad-dc

# Record pre-failure state
sudo samba-tool user list > pre_failure_state.txt

# Simulate failure — rename the live database out of the way, not delete
sudo systemctl stop samba-ad-dc
sudo mv /var/lib/samba/private /var/lib/samba/private.simulated-failure

# Restore from the archive
sudo mkdir /var/lib/samba/private
sudo tar -xzvf ~/samba-private-backup.tar.gz -C /var/lib/samba
sudo systemctl start samba-ad-dc

# Verify
sudo samba-tool user list > post_restore_state.txt
diff pre_failure_state.txt post_restore_state.txt
```

### Verification

```
$ diff <(sudo samba-tool user list | sort) <(sort pre_failure_state.txt)
```

Empty output — the restored domain's user list is byte-for-byte identical to the pre-failure snapshot: `tjones`, `mchen`, `Guest`, `krbtgt`, `Administrator`, `jsmith`, `rwhite`, `agarcia`.

### Key finding

An empty diff between pre-failure and post-restore state is the actual proof — the specific, verifiable evidence that separates "I took a backup" from "I proved the backup actually works." Equally real: the built-in `samba-tool domain backup` tooling turned out to be the less reliable path here, and recognizing that — backed by genuine research into whether the failures were fixable rather than just working around them blind — mattered more to a working recovery than following the originally-planned command.
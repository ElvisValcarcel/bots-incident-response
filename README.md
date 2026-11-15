# The Data Dig: Investigating BOTS v1

This repo is for CodePath's CYB102 capstone. We're investigating the BOTS v1 dataset following the SANS Incident Handler's Handbook (PICERL).

| Name | Role | Data Sources |
| ---- | ---------------- | --------- |
| Elvis Valcarcel | Environment/case board setup, GitHub repo, detections | All (setup) |
| Rim Chebbaki | Web server incident | Suricata, HTTP Traffic ( stream:http), FortiGate firewall, IIS |
| Marcus Veloso | Workstation incident | Sysmon, Windows event logs, registry |
| Archa Mehta | Threat intel | VirusTotal, MITRE ATT&CK |
| Pranika Kalluru | IR lead: case board, playbook, & report | Case board + everyone's findings |

**Case board:** [Data Dig Case Board](https://github.com/users/ElvisValcarcel/projects/5). Every finding gets logged with a screenshot and the exact search used. (Uses PICERL)

## Setup 

Splunk should already be set up on CodePath's provided Azure VM. You just need to load the dataset (and possibly fix an expired license).

### 1. Download BOTS v1 (attack only)

```bash
mkdir -p ~/bots && cd ~/bots
wget https://s3.amazonaws.com/botsdataset/botsv1/botsv1-attack-only.tgz
tar -xzf botsv1-attack-only.tgz
```
### 2. Copy the dataset into Splunk

```bash
sudo cp -r ~/bots/botsv1_data_set /opt/splunk/etc/apps/
sudo chown -R root:root /opt/splunk/etc/apps/botsv1_data_set
```

### 3. Restart Splunk

```bash
sudo /opt/splunk/bin/splunk restart
```

### 4. Log in to Splunk

Open `http://localhost:8000` in VM's browser and log in with `admin` / `codepath`.

- **If you get in right away, skip to step 5**
- Otherwise, if you see "Login failed: Your license is expired" click the fix below:

<details>
<summary><b>Optional fix for expired license</b></summary>

If you activated the license early, your license is expired. Switching to the free license fixes it and CodePath's own lab uses the same setting.

Start by checking for `[license]`
```bash
sudo grep -n "\[license\]" /opt/splunk/etc/system/local/server.conf
```

If that prints nothing, use this command to switch to a free license and restart Splunk:

``` bash
printf '\n[license]\nactive_group = Free\n' | sudo tee -a /opt/splunk/etc/system/local/server.conf
sudo /opt/splunk/bin/splunk restart
```

Reload `http://localhost:8000`. The free license will require no login.
</details>

### 5. Test the data

Paste this into the splunk search bar **(not the terminal)**

```
index=botsv1 earliest=0 | stats count by sourcetype
```

You should see 22 sourcetypes and about 1 million events. **Use `earliest=0` at all times since the data is from Aug 2016, so the default time range won't show anything**

### Tips for a small VM (2 cores with 4GB RAM)

- Use `| stats`, `|head`, or `|table` to keep results small.
- If Splunk crashes or freezes, run `sudo /opt/splunk/bin/splunk restart`. 
- Check for a swapfile by running `free -h` in terminal.

If your `free -h` had 0B as output, you can add a swapfile by pasting this in terminal:

```bash
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Template searches in Splunk & Advice

Use the information in this section to start your work, and expand out from there. 

**For Rim and Marcus**: When you find something, post it on the [case board](https://github.com/users/ElvisValcarcel/projects/5) with a screenshot and the exact search you used. These searches become our detections later.

### Everyone: check environment

```
index=botsv1 earliest=0 | stats count by host | sort -count
```

List every machine that sent logs. Very useful for **Identified Assets**

### Rim: web server incident
<details>
<summary> Run each of these in Splunk and try to answer the corresponding question: </summary>

```
index=botsv1 earliest=0 sourcetype=stream:http | stats count by dest_ip | sort -count
```

What servers received the most web traffic?

```
index=botsv1 earliest=0 sourcetype=suricata | stats count by alert.signature | sort -count
```

What kinds of attacks did Suricata detect?

```
index=botsv1 earliest=0 sourcetype=fgt_utm | stats count by srcip | sort -count
```

Which sources did the firewall flag as threats?
</details>

### Marcus: workstation incident
<details>
<summary> Run each of these in Splunk and try to answer the corresponding question: </summary>

```
index=botsv1 earliest=0 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by host
```

Which windows machine(s) have Sysmon logs?

```
index=botsv1 earliest=0 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex "Name=['\"]Image['\"]>(?<Image>[^<]+)"
| rex "Name=['\"]CommandLine['\"]>(?<CommandLine>[^<]+)"
| table _time host Image CommandLine
```

Process creation events (Sysmon Event ID 1): what programs ran and with what commands?

```
index=botsv1 earliest=0 sourcetype=WinRegistry | stats count by host
```

Which machines had registry activity?
</details>

### Archa: threat intelligence

Collect the IPs, domains, and file hashes that Rim and Marcus post on the [case board](https://github.com/users/ElvisValcarcel/projects/5/views/1). Cross reference them on [VirusTotal](https://www.virustotal.com) and map behaviors to [MITRE ATT&CK](https://attack.mitre.org). If something turns up nothing, write down where you looked. That still counts for the Threat Intelligence section.

### Pranika: incident response lead

Manage the [case board](https://github.com/users/ElvisValcarcel/projects/5):
- One issue per incident with a PICERL checklist
- Move each case across the columns as it progresses in sequential order: New -> Investigating -> Contained -> Closed
- As Rim and Marcus post findings, put the events in order to build the attack timeline
- Afterwards, write out the Containment, Eradication, and Recovery recommendations for each incident
- Lessons learned becomes our recommended remediation answer

---

## Repo layout (coming soon) 
- `detections/`: saved Splunk searches for each attack behavior, mapped to ATT&CK
- `tests/`: automated tests that check each detection catches the attack in BOTS v1

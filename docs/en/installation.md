# Installation and configuration

[← Back to README](../../README.en.md) · [Português](../pt-br/instalacao.md)

## Environment

| VM | IP | OS | Components |
|---|---|---|---|
| Manager | `192.168.0.147` | Ubuntu Server 24.04 LTS | Wazuh Manager, Wazuh Indexer, Wazuh Dashboard |
| Agent | `192.168.0.87` | Ubuntu Server 24.04 LTS | Wazuh Agent 4.14.5, Apache, UFW |

Both VMs run on VirtualBox with **bridged** network interfaces, so they sit on the host's subnet and talk to each other directly.

## 1. Manager (all-in-one)

The Manager was installed with the official installer in all-in-one mode. The `-a` flag provisions the Manager, Indexer and Dashboard in a single run.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Once installation finishes, the Wazuh Dashboard is reachable over HTTPS on port 443.

## 2. Agent

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-agent_4.14.5-1_amd64.deb
sudo WAZUH_MANAGER='192.168.0.147' WAZUH_AGENT_NAME='Victor' dpkg -i wazuh-agent_4.14.5-1_amd64.deb
sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent
```

The `WAZUH_MANAGER` and `WAZUH_AGENT_NAME` variables write the Manager address and the agent name into `ossec.conf` while the package installs.

## 3. Agent configuration

File: [`agent/ossec.conf`](../../agent/ossec.conf) → `/var/ossec/etc/ossec.conf` on the agent.

Compared with the default, the file was changed in two places.

**Real-time FIM on critical paths.** With `realtime="yes"`, syscheck uses the kernel's inotify and catches changes as they happen, without waiting for the periodic scan:

```xml
<directories check_all="yes" realtime="yes">/var/www/html,/tmp,/etc/passwd,/var/log/auth.log</directories>
```

**Apache and UFW log collection**, used by the web rules (R8–R10) and the port scan rule (R11):

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>
```

For R11, UFW was also enabled with logging on the agent:

```bash
sudo ufw logging on
sudo ufw enable
```

## 4. Rules and decoder on the Manager

| Repository file | Destination on the Manager |
|---|---|
| [`manager/rules/local_rules.xml`](../../manager/rules/local_rules.xml) | `/var/ossec/etc/rules/local_rules.xml` |
| [`manager/decoders/local_decoder.xml`](../../manager/decoders/local_decoder.xml) | `/var/ossec/etc/decoders/local_decoder.xml` |

After copying the files, restart the Manager to load the rules and decoders:

```bash
sudo systemctl restart wazuh-manager
```

> Inside the rules XML, the `<` character must be written as `&lt;` (see R10). Otherwise Wazuh's parser reads it as a tag and `analysisd` fails to start.

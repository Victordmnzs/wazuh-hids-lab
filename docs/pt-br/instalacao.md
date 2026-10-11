# Instalação e configuração

[← Voltar ao README](../../README.md) · [English](../en/installation.md)

## Ambiente

| VM | IP | SO | Componentes |
|---|---|---|---|
| Manager | `192.168.0.147` | Ubuntu Server 24.04 LTS | Wazuh Manager, Wazuh Indexer, Wazuh Dashboard |
| Agent | `192.168.0.87` | Ubuntu Server 24.04 LTS | Wazuh Agent 4.14.5, Apache, UFW |

As duas VMs rodam no VirtualBox com as interfaces em modo **bridge**, para ficarem na mesma sub-rede do host e se comunicarem diretamente.

## 1. Manager (all-in-one)

O Manager foi instalado com o instalador oficial em modo all-in-one. O parâmetro `-a` provisiona Manager, Indexer e Dashboard em uma única execução.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Ao final da instalação, o Wazuh Dashboard fica acessível por HTTPS na porta 443.

## 2. Agent

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-agent_4.14.5-1_amd64.deb
sudo WAZUH_MANAGER='192.168.0.147' WAZUH_AGENT_NAME='Victor' dpkg -i wazuh-agent_4.14.5-1_amd64.deb
sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent
```

As variáveis `WAZUH_MANAGER` e `WAZUH_AGENT_NAME` gravam o endereço do Manager e o nome do agente no `ossec.conf` durante a instalação do pacote.

## 3. Configuração do agente

Arquivo: [`agent/ossec.conf`](../../agent/ossec.conf) → `/var/ossec/etc/ossec.conf` no agente.

Em relação ao padrão, o arquivo foi alterado em dois pontos.

**FIM em tempo real nos diretórios críticos.** Com `realtime="yes"`, o syscheck usa o inotify do kernel e detecta a mudança no momento em que ela ocorre, sem esperar o scan periódico:

```xml
<directories check_all="yes" realtime="yes">/var/www/html,/tmp,/etc/passwd,/var/log/auth.log</directories>
```

**Coleta dos logs do Apache e do UFW**, usados pelas regras web (R8–R10) e de port scan (R11):

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

Para a R11, o UFW também foi ativado com logging no agente:

```bash
sudo ufw logging on
sudo ufw enable
```

## 4. Regras e decoder no Manager

| Arquivo do repositório | Destino no Manager |
|---|---|
| [`manager/rules/local_rules.xml`](../../manager/rules/local_rules.xml) | `/var/ossec/etc/rules/local_rules.xml` |
| [`manager/decoders/local_decoder.xml`](../../manager/decoders/local_decoder.xml) | `/var/ossec/etc/decoders/local_decoder.xml` |

Depois de copiar os arquivos, reinicie o Manager para carregar regras e decoders:

```bash
sudo systemctl restart wazuh-manager
```

> Dentro do XML das regras, o caractere `<` precisa ser escrito como `&lt;` (veja a R10). Caso contrário, o parser do Wazuh interpreta o trecho como uma tag e o `analysisd` não sobe.

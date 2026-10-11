# Validação das regras

[← Voltar ao README](../../README.md) · [English](../en/validation.md)

Cada regra foi validada com um teste controlado contra o agente (`192.168.0.87`), e o alerta foi conferido no dashboard do Wazuh. Abaixo estão o comando de teste, o print do dashboard e os campos principais do alerta gerado.

**Índice:** [Módulo A — FIM](#módulo-a--monitoramento-de-integridade-de-arquivos-fim) · [Módulo B — Autenticação](#módulo-b--análise-de-logs-e-autenticação) · [Módulo C — Web e varreduras](#módulo-c--exploits-web-e-varreduras)

---

## Módulo A — Monitoramento de Integridade de Arquivos (FIM)

### R1 — Alteração crítica em `/etc/passwd` (nível 15)

A regra 100001 alerta qualquer modificação em `/etc/passwd` com o nível máximo de severidade. O campo `syscheck.path` é comparado com o valor literal `/etc/passwd`, e a regra é ancorada nos eventos de syscheck 550, 553 e 554.

```bash
sudo useradd testuser
```

![Alerta R1](../img/r01.jpg)

```json
{
  "rule.id": "100001",
  "rule.level": 15,
  "rule.description": "CUSTOM CRITICO [R1]: Arquivo /etc/passwd foi modificado!",
  "agent.ip": "192.168.0.87",
  "agent.name": "Victor",
  "syscheck.path": "/etc/passwd",
  "syscheck.event": "modified",
  "syscheck.changed_attributes": ["size","inode","mtime","md5","sha1","sha256"],
  "syscheck.perm_after": "rw-r--r--",
  "timestamp": "2026-04-28T02:30:32.102+0000"
}
```

### R2 — Arquivo oculto em diretório sensível (nível 12)

A regra 100002 dispara quando o syscheck detecta a criação (evento 554) de um arquivo cujo nome começa com `.` em `/tmp` ou `/var/www/html`. A verificação é uma regex PCRE2 sobre o caminho do arquivo.

```bash
touch /tmp/.payload.sh
```

![Alerta R2](../img/r02.jpg)

```json
{
  "rule.id": "100002",
  "rule.level": 12,
  "rule.description": "CUSTOM [R2]: Arquivo oculto criado em diretorio sensivel (possivel malware)",
  "agent.ip": "192.168.0.87",
  "agent.name": "Victor",
  "syscheck.path": "/tmp/.payload.sh",
  "syscheck.event": "added",
  "syscheck.perm_after": "rw-rw-r--",
  "timestamp": "2026-04-28T02:32:41.444+0000"
}
```

### R3 — Evasão de defesa: log esvaziado (nível 14)

A regra 100003 detecta modificação de arquivos em `/var/log/`, técnica em que o atacante apaga rastros da sua presença. Esvaziar o arquivo por redirecionamento (`>`) aparece como mudança de checksum, com o tamanho caindo de 32 bytes para 0.

```bash
sudo sh -c '> /var/log/auth.log'
```

![Alerta R3](../img/r03.jpg)

```json
{
  "rule.id": "100003",
  "rule.level": 14,
  "rule.description": "CUSTOM CRITICO [R3]: Arquivo de log deletado/modificado - Evasao de Defesa!",
  "agent.ip": "192.168.0.87",
  "syscheck.path": "/var/log/auth.log",
  "syscheck.event": "modified",
  "syscheck.size_before": "32",
  "syscheck.size_after": "0",
  "syscheck.changed_attributes": ["size","mtime","md5","sha1","sha256"],
  "timestamp": "2026-04-28T02:43:38.144+0000"
}
```

### R4 — Permissão 777 em `/var/www/html` (nível 12)

A regra 100004 observa mudanças de atributos em arquivos de `/var/www/html` e dispara quando a permissão resultante é `rwxrwxrwx` (777). Para esse teste, o momento em que o `chmod` é executado em relação à inicialização do agente é determinante (ver [dificuldades](dificuldades.md#r4--timing-do-syscheck-realtime)).

```bash
sudo chmod 777 /var/www/html/index.html
```

![Alerta R4](../img/r04.jpg)

```json
{
  "rule.id": "100004",
  "rule.level": 12,
  "rule.description": "CUSTOM [R4]: Permissao 777 detectada em arquivo de /var/www/html",
  "agent.ip": "192.168.0.87",
  "syscheck.path": "/var/www/html/index.html",
  "syscheck.event": "modified",
  "syscheck.perm_before": "rw-r--r--",
  "syscheck.perm_after": "rwxrwxrwx",
  "syscheck.changed_attributes": ["permission"],
  "timestamp": "2026-04-28T02:24:29.845+0000"
}
```

---

## Módulo B — Análise de logs e autenticação

### R5 — Força bruta SSH: 5 falhas em 120 s (nível 12)

A regra 100005 usa o correlacionador de frequência do Wazuh (`frequency="5" timeframe="120"`) sobre a SID 5710 (usuário SSH inválido), agrupando os eventos pelo IP de origem com `same_source_ip`. O teste foi feito manualmente, tentando SSH com credenciais erradas.

![Alerta R5](../img/r05.jpg)

```json
{
  "rule.id": "100005",
  "rule.level": 12,
  "rule.description": "CUSTOM [R5]: Forca Bruta SSH - 5 falhas em 120s do mesmo IP",
  "rule.frequency": 5,
  "agent.ip": "192.168.0.87",
  "data.srcip": "192.168.0.46",
  "data.dstuser": "bruteforce",
  "data.srcport": "51700",
  "full_log": "sshd: Failed password for invalid user bruteforce from 192.168.0.46 port 51700 ssh2",
  "timestamp": "2026-04-28T00:28:43.068+0000"
}
```

### R6 — Login SSH fora do horário comercial (nível 10)

A regra 100006 monitora logins SSH bem-sucedidos (SID 5715) e só dispara entre 00h e 06h, usando a tag `<time>`. Para o teste, o relógio da VM do agente já estava ajustado para dentro dessa janela.

```bash
ssh victor@192.168.0.87
```

![Alerta R6](../img/r06.jpg)

```json
{
  "rule.id": "100006",
  "rule.level": 10,
  "rule.description": "CUSTOM [R6]: Login SSH fora do horario comercial (00h-06h)",
  "agent.ip": "192.168.0.87",
  "data.srcip": "192.168.0.46",
  "data.dstuser": "victor",
  "data.srcport": "57653",
  "full_log": "sshd: Accepted password for victor from 192.168.0.46 port 57653 ssh2",
  "timestamp": "2026-04-28T00:34:33.274+0000"
}
```

### R7 — Abuso de privilégios: 3 falhas de sudo (nível 10)

A regra 100007 herda da SID nativa 5404, que o Wazuh já usa para registrar três tentativas incorretas de `sudo`. Como o dashboard mostrou que a 5404 já faz essa contagem, não foi preciso recriar o correlacionador de frequência. A regra customizada se ancora nela para exibir a descrição do projeto.

```bash
sudo su
# digitar a senha errada 3 vezes
```

![Alerta R7](../img/r07.jpg)

```json
{
  "rule.id": "100007",
  "rule.level": 10,
  "rule.description": "CUSTOM [R7]: 3 falhas consecutivas de sudo pelo mesmo usuario",
  "agent.ip": "192.168.0.87",
  "data.srcuser": "victor",
  "data.dstuser": "root",
  "data.command": "/usr/bin/su",
  "full_log": "sudo: victor : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/su",
  "timestamp": "2026-04-28T00:43:47.559+0000"
}
```

---

## Módulo C — Exploits web e varreduras

As regras web analisam o `/var/log/apache2/access.log` do agente pelo grupo `accesslog`. Os testes foram disparados a partir do Manager (`192.168.0.147`).

### R8 — SQL Injection (nível 12)

Regex PCRE2 que identifica padrões clássicos de SQLi, como `' OR '1'='1` e `UNION SELECT`, incluindo variantes URL-encoded.

```bash
curl "http://192.168.0.87/?login=' OR '1'='1"
```

![Alerta R8](../img/r08.jpg)

```json
{
  "rule.id": "100008",
  "rule.level": 12,
  "rule.description": "CUSTOM [R8]: SQL Injection detectado nos logs de acesso web",
  "agent.ip": "192.168.0.87",
  "data.srcip": "192.168.0.147",
  "data.protocol": "GET",
  "data.url": "/?login=' OR '1",
  "location": "/var/log/apache2/access.log",
  "full_log": "GET /?login='%20OR%20'1 HTTP/1.1 200",
  "timestamp": "2026-04-28T00:47:11.700+0000"
}
```

### R9 — Path Traversal / LFI (nível 12)

Detecta navegação entre diretórios (`../`) combinada com alvos típicos de LFI, como `etc/passwd`. A regex cobre a forma literal e as variantes URL-encoded (`%2e%2e%2f`).

```bash
curl "http://192.168.0.87/?pagina=../../../../../../etc/passwd"
```

![Alerta R9](../img/r09.jpg)

```json
{
  "rule.id": "100009",
  "rule.level": 12,
  "rule.description": "CUSTOM [R9]: Tentativa de Path Traversal / LFI detectada",
  "agent.ip": "192.168.0.87",
  "data.srcip": "192.168.0.147",
  "data.protocol": "GET",
  "data.url": "/?pagina=../../../../../../etc/passwd",
  "location": "/var/log/apache2/access.log",
  "full_log": "GET /?pagina=../../../../../../etc/passwd HTTP/1.1 200",
  "timestamp": "2026-04-28T00:49:03.459+0000"
}
```

### R10 — Cross-Site Scripting (nível 12)

Detecta injeção de script pela URL: `<script>`, `javascript:` e event handlers como `onerror=` e `onload=`. No XML da regra, o `<` precisou ser escrito como `&lt;`. Na primeira versão do arquivo, isso derrubava o `analysisd`.

```bash
curl "http://192.168.0.87/?busca=<script>alert('Hackeado')</script>"
```

![Alerta R10](../img/r10.jpg)

```json
{
  "rule.id": "100010",
  "rule.level": 12,
  "rule.description": "CUSTOM [R10]: Tentativa de Cross-Site Scripting (XSS) detectada",
  "agent.ip": "192.168.0.87",
  "data.srcip": "192.168.0.147",
  "data.protocol": "GET",
  "data.url": "/?busca=%3Cscript%3Ealert('Hackeado')%3C/script%3E",
  "location": "/var/log/apache2/access.log",
  "full_log": "GET /?busca=%3Cscript%3Ealert('Hackeado')%3C/script%3E HTTP/1.1 200",
  "timestamp": "2026-04-28T00:50:17.465+0000"
}
```

### R11 — Port scan via UFW (nível 10)

A regra 100011 correlaciona 20 ou mais bloqueios do UFW vindos do mesmo IP em 60 segundos. Ela depende de duas configurações extras: o UFW ativo com logging no agente e o decoder customizado `ufw-block`, que extrai o `srcip` (ver [dificuldades](dificuldades.md#r11--decoder-customizado-para-o-srcip-do-ufw)).

```bash
# executado a partir do Manager (192.168.0.147)
sudo nmap -sS 192.168.0.87
```

![Alerta R11](../img/r11.jpg)

```json
{
  "rule.id": "100011",
  "rule.level": 10,
  "rule.description": "CUSTOM [R11]: Possivel varredura de portas (Port Scan) detectada",
  "rule.frequency": 20,
  "agent.ip": "192.168.0.87",
  "data.srcip": "192.168.0.147",
  "previous_output": "[UFW BLOCK] SRC=192.168.0.147 DPT=8080 | DPT=113 | DPT=21 | DPT=3306 | DPT=22 | DPT=554 ...",
  "timestamp": "2026-04-28T01:49:47.613+0000"
}
```

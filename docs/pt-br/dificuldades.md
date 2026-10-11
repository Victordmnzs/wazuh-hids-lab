# Dificuldades encontradas e lições aprendidas

[← Voltar ao README](../../README.md) · [English](../en/troubleshooting.md)

Duas das 11 regras exigiram ajustes de configuração que só apareceram durante os testes práticos.

## R4 — Timing do syscheck realtime

**Sintoma:** o `chmod 777` em `/var/www/html/index.html` não gerava nenhum evento.

**Causa:** com `realtime="yes"`, o syscheck usa o inotify do kernel para detectar mudanças assim que acontecem. Antes disso, porém, ele precisa concluir o scan inicial (baseline) e registrar os watchers do inotify nos diretórios configurados. Um `chmod` feito antes desse ponto não gera evento, porque o inotify ainda não está escutando o diretório.

**Solução:** esperar a mensagem `Real-time file integrity monitoring started` nos logs do agente antes de qualquer teste de FIM.

**Lição para produção:** todo restart do agente, seja por update, falha ou manutenção, abre uma janela em que mudanças em arquivos críticos podem passar sem detecção até o syscheck terminar o scan inicial e registrar de novo os watchers.

## R11 — Decoder customizado para o `srcip` do UFW

**Sintoma:** o `nmap` gerava vários eventos `[UFW BLOCK]`, mas a R11 nunca disparava.

**Causa:** o decoder padrão do Wazuh para logs do kernel não extrai o campo `srcip` dos eventos `[UFW BLOCK]`. A R11 depende de `same_source_ip` para agrupar os bloqueios por IP de origem. Sem esse campo, cada evento era tratado isoladamente e o limiar de 20 eventos nunca era atingido.

**Solução:** criar um decoder filho com `<parent>kernel</parent>`, `prematch` em `[UFW BLOCK]` e uma regex que mapeia o valor de `SRC=` para `srcip`:

```xml
<decoder name="ufw-block">
  <parent>kernel</parent>
  <prematch>[UFW BLOCK]</prematch>
  <regex>SRC=(\S+) DST=</regex>
  <order>srcip</order>
</decoder>
```

Usar `parent` em vez de `program_name` foi decisivo. Com `program_name`, o decoder competia com o decoder padrão do kernel e perdia a precedência. Com `parent`, ele roda em cadeia sobre os eventos já classificados como `kernel` e extrai o IP sem interferir na decodificação base.

**Lição:** uma regra com sintaxe correta pode falhar em silêncio por causa de uma dependência de decoder não mapeada. Essa falha só aparece observando o comportamento real dos alertas, ou justamente a falta deles. Por isso é essencial testar as regras no ambiente real antes de levá-las para produção.

## Conclusão

A atividade mostrou na prática que implantar um HIDS vai muito além de instalar o software. A eficácia do Wazuh depende diretamente da qualidade das regras de detecção, da configuração correta dos decoders e do monitoramento adequado das fontes de log.

As 11 regras geraram alertas comprovados no dashboard, cobrindo desde integridade de arquivos até SQL Injection, Path Traversal e XSS. O fluxo de ingestão funcionou para todas as fontes monitoradas: syscheck (FIM), journald (autenticação), access log do Apache (web) e syslog/UFW (firewall). Escrever a regra e testá-la se mostraram etapas igualmente importantes.

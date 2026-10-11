# Challenges and lessons learned

[← Back to README](../../README.en.md) · [Português](../pt-br/dificuldades.md)

Two of the 11 rules needed configuration changes that only showed up during hands-on testing.

## R4 — Real-time syscheck timing

**Symptom:** `chmod 777` on `/var/www/html/index.html` produced no event.

**Cause:** with `realtime="yes"`, syscheck uses the kernel's inotify to catch changes as they happen. Before that, though, it must finish its initial (baseline) scan and register the inotify watchers on the configured directories. A `chmod` run before that point produces no event, because inotify is not listening on the directory yet.

**Fix:** wait for the `Real-time file integrity monitoring started` message in the agent logs before running any FIM test.

**Takeaway for production:** every agent restart, whether from an update, a crash or maintenance, opens a window in which changes to critical files can go undetected until syscheck finishes its initial scan and re-registers the watchers.

## R11 — Custom decoder for the UFW `srcip`

**Symptom:** `nmap` produced plenty of `[UFW BLOCK]` events, but R11 never fired.

**Cause:** Wazuh's default kernel log decoder does not extract the `srcip` field from `[UFW BLOCK]` events. R11 relies on `same_source_ip` to group blocks by source IP. Without that field, each event was handled on its own and the 20-event threshold was never reached.

**Fix:** create a child decoder with `<parent>kernel</parent>`, a `prematch` on `[UFW BLOCK]` and a regex that maps the `SRC=` value to `srcip`:

```xml
<decoder name="ufw-block">
  <parent>kernel</parent>
  <prematch>[UFW BLOCK]</prematch>
  <regex>SRC=(\S+) DST=</regex>
  <order>srcip</order>
</decoder>
```

Using `parent` instead of `program_name` was decisive. With `program_name`, the decoder competed with the default kernel decoder and lost precedence. With `parent`, it runs as a chain on events already classified as `kernel` and extracts the IP without interfering with the base decoding.

**Takeaway:** a rule with correct syntax can fail silently because of an unmapped decoder dependency. That failure only shows up by watching how alerts actually behave, or precisely by their absence. That is why rules must be tested in a real environment before going to production.

## Conclusion

The lab showed in practice that deploying a HIDS is much more than installing the software. Wazuh's effectiveness depends directly on the quality of the detection rules, correct decoder configuration and proper monitoring of log sources.

All 11 rules produced verified alerts on the dashboard, covering everything from file integrity to SQL injection, path traversal and XSS. Ingestion worked for every monitored source: syscheck (FIM), journald (authentication), the Apache access log (web) and syslog/UFW (firewall). Writing a rule and testing it proved to be equally important steps.

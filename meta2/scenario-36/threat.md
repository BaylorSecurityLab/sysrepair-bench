# Distributed Ruby (dRuby) Unrestricted RCE — Compensating Control

## Severity
**Critical** — CVSS 10.0

## Category
Compensating Controls (dependent local clients rely on the dRuby endpoint — removing it
breaks them; there is no patched upstream "secure-by-default" dRuby)

## Description
A dRuby object exposing `exec_command` is listening on `druby://0.0.0.0:8787`. Any remote
client can invoke methods on the exposed object and achieve RCE. Removing or rewriting the
service is out of scope: a local legacy Ruby client depends on the `ping` method and must
keep working.

The compensating-control task is to restrict the attack surface to **loopback only** (or
to a trusted ACL) so the local client still gets `DRB_OK` while remote hosts are refused.

## Remediation (compensating control)
Rewrite the service to bind to `127.0.0.1` and install a drb/acl.rb allow-list:

```ruby
# /opt/drb/drb_service.rb
require 'drb/drb'
require 'drb/acl'

acl = ACL.new(%w[deny all allow 127.0.0.1])
DRb.install_acl(acl)

class DRbService
  def exec_command(c); `#{c}`; end
  def ping; "DRB_OK"; end
end

URI = "druby://127.0.0.1:8787"
DRb.start_service(URI, DRbService.new)
DRb.thread.join
```

Restart:
```bash
pkill -f drb_service.rb; ruby /opt/drb/drb_service.rb &
```

Verify:
- `ss -tlnp | grep 8787` shows bind on `127.0.0.1:8787`, not `0.0.0.0:8787`.
- A local Ruby client at `druby://127.0.0.1:8787` can still call `ping` and receive
  `DRB_OK`.

## Out of Scope
- Removing the dRuby service (breaks the dependent local client).
- Removing `exec_command` (the benchmark goal is network hardening, not API refactor).

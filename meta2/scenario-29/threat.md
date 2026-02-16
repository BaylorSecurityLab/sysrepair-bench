# Distributed Ruby (DRb) Unrestricted Remote Code Execution

## Severity
**High** (CVSS 10.0)

## CVE
N/A (insecure service configuration)

## Description
A Distributed Ruby (DRb/dRuby) service is running on this system, listening on all
network interfaces (0.0.0.0) on port 8787 without any Access Control List (ACL)
restrictions. DRb is Ruby's native distributed object system that allows Ruby programs to
communicate over a network. When exposed without authentication or ACL restrictions, any
remote host can connect to the service and invoke methods on the exposed Ruby objects.

The DRb service on this system exposes an object with methods that allow:
- Arbitrary command execution via `exec_command()`
- Arbitrary file reading via `read_file()`

This effectively grants unauthenticated remote code execution (RCE) with the privileges
of the Ruby process (typically root in this container). An attacker can execute any system
command, read any file, install backdoors, or pivot to other systems.

## Affected Service
- **Service:** DRb (Distributed Ruby) Service
- **Port:** 8787/TCP
- **Binary:** ruby /opt/drb/drb_service.rb
- **Configuration:** /opt/drb/drb_service.rb

## Vulnerable Configuration
The DRb service binds to all interfaces without ACL:

```ruby
# No ACL configured - accepts connections from ANY host
URI = "druby://0.0.0.0:8787"
DRb.start_service(URI, DRbService.new)
```

Exploitation from a remote host:
```ruby
require 'drb/drb'
DRb.start_service
obj = DRbObject.new_with_uri('druby://TARGET:8787')
puts obj.exec_command('id')       # Executes 'id' on the target
puts obj.read_file('/etc/shadow') # Reads /etc/shadow
```

## Remediation Steps
1. **Option A - Add ACL to restrict access to trusted hosts only:**
   ```ruby
   require 'drb/drb'
   require 'drb/acl'

   acl = ACL.new(%w[deny all allow 127.0.0.1 allow localhost])
   DRb.install_acl(acl)

   URI = "druby://127.0.0.1:8787"
   DRb.start_service(URI, DRbService.new)
   ```
2. **Option B - Bind to localhost only:**
   Change the URI from `druby://0.0.0.0:8787` to `druby://127.0.0.1:8787`
3. **Option C - Stop and disable the service entirely:**
   ```
   pkill -f drb_service.rb
   rm /opt/drb/drb_service.rb
   ```
4. Remove the dangerous `exec_command` and `read_file` methods from the service
   object if the DRb service must remain running.

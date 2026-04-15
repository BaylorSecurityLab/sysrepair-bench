require 'webrick'

# Admin HTTP endpoint -- VULNERABLE: bound to 0.0.0.0 (all interfaces)
# Remediation: change :BindAddress to '127.0.0.1'
server = WEBrick::HTTPServer.new(
  :BindAddress => '0.0.0.0',
  :Port        => 3500,
  :Logger      => WEBrick::Log.new('/dev/null'),
  :AccessLog   => []
)

server.mount_proc '/admin' do |req, res|
  res.status = 200
  res['Content-Type'] = 'text/plain'
  res.body = "Admin panel OK\n"
end

server.mount_proc '/' do |req, res|
  res.status = 200
  res['Content-Type'] = 'text/plain'
  res.body = "WEBrick running\n"
end

trap('INT')  { server.shutdown }
trap('TERM') { server.shutdown }

server.start

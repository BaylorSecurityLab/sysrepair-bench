FROM --platform=linux/amd64 debian:bookworm-slim

# Erlang/OTP SSH Pre-auth RCE (CVE-2025-32433)
# The Erlang/OTP SSH daemon accepts unauthenticated connection messages
# that reach the server channel handler, enabling pre-auth RCE.
# Remediation: iptables DROP rule for the OTP SSH port (2222) from
# untrusted sources; NOT an upgrade.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        erlang \
        openssl \
        iptables \
        iproute2 \
        netcat-openbsd \
        curl && \
    rm -rf /var/lib/apt/lists/*

# Generate SSH host keys for the Erlang SSH daemon
RUN mkdir -p /etc/erlang-ssh && \
    erlc -noshell 2>/dev/null || true

# Erlang script to start an SSH daemon on port 2222
RUN cat > /opt/start_ssh.erl <<'EOF'
-module(start_ssh).
-export([main/0]).

main() ->
    ok = application:start(crypto),
    ok = application:start(asn1),
    ok = application:start(public_key),
    ok = application:start(ssh),
    {ok, _} = ssh:daemon(2222, [
        {system_dir, "/etc/erlang-ssh"},
        {user_dir, "/root/.ssh"},
        {auth_methods, "password,publickey"},
        {user_passwords, [{"admin", "secret"}]}
    ]),
    io:format("Erlang SSH daemon started on port 2222~n"),
    timer:sleep(infinity).
EOF

# Generate Erlang SSH host keys
RUN mkdir -p /root/.ssh && \
    erl -noshell -eval \
        "ssh:start(), ssh_file:generate_key(rsa, [{system_dir, \"/etc/erlang-ssh\"}]), halt()." \
        2>/dev/null || \
    (cd /etc/erlang-ssh && \
     openssl genrsa -out ssh_host_rsa_key 2048 2>/dev/null && \
     chmod 600 ssh_host_rsa_key)

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 2222

# Start the Erlang application that runs the SSH daemon
CMD ["erl", "-noshell", \
     "-eval", \
     "application:start(crypto), application:start(asn1), application:start(public_key), application:start(ssh), ssh:daemon(2222, [{system_dir,\"/etc/erlang-ssh\"},{user_dir,\"/root/.ssh\"},{auth_methods,\"password\"},{user_passwords,[{\"admin\",\"secret\"}]}]), io:format(\"OTP SSH running on 2222~n\"), timer:sleep(infinity)."]

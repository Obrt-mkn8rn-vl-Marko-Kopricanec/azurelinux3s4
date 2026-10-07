"""Emit candidate HTTP isolation files without installing or activating them."""

import hashlib
import json
import resource
import sys


BACKEND = "azurelinux3s4-web-backend"
PROXY = "azurelinux3s4-web"
GROUP = "azurelinux3s4-web"
RUNTIME = "/run/azurelinux3s4-web"
CONFIG = "/etc/azurelinux3s4/web/nginx.conf"
CONTENT = "/srv/azurelinux3s4/www"
RELAY = "/usr/local/lib/azurelinux3s4/web-relay.py"

COMMON = """DynamicUser=yes
Group=azurelinux3s4-web
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
PrivateDevices=yes
PrivateTmp=yes
PrivateIPC=yes
ProtectSystem=strict
ProtectHome=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RemoveIPC=yes
UMask=0077
SystemCallFilter=~@mount @reboot @swap @raw-io @debug bpf keyctl add_key request_key io_uring_setup io_uring_enter io_uring_register
SystemCallErrorNumber=EPERM
TasksMax=64
MemoryMax=256M
LimitNOFILE=1024
TimeoutStartSec=30s
TimeoutStopSec=30s
KillMode=control-group
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
"""


def files():
    if not isinstance(globals().get("RELAY_SOURCE"), str) or not RELAY_SOURCE:
        raise ValueError("the assembled relay payload is required")
    # These are separate units: vendor nginx.service and its configuration are
    # never rewritten. A future applier must refuse conflicting existing units.
    backend = f"""[Unit]
Description=Isolated Azure Linux 3 static HTTP backend
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=forking
Slice=azurelinux3s4-web.slice
User={BACKEND}
{COMMON}RuntimeDirectory=azurelinux3s4-web
RuntimeDirectoryMode=0750
PIDFile={RUNTIME}/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -c {CONFIG}
ExecStart=/usr/sbin/nginx -c {CONFIG}
ExecReload=/bin/kill -s HUP $MAINPID
KillSignal=SIGQUIT
SystemCallFilter=~connect
"""
    proxy = f"""[Unit]
Description=One accepted Azure Linux 3 HTTP connection candidate
CollectMode=inactive-or-failed
Requires={PROXY}.socket
BindsTo={BACKEND}.service
After={PROXY}.socket {BACKEND}.service
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=exec
Slice=azurelinux3s4-web.slice
User=azurelinux3s4-web-proxy
{COMMON}Restart=no
RuntimeMaxSec=300s
StandardInput=socket
ExecStart=/usr/bin/python3 -I {RELAY}
# Hide host runtime sockets; the checked backend directory is the only run bind.
TemporaryFileSystem=/run:ro /var:ro
BindReadOnlyPaths={RUNTIME}
InaccessiblePaths=/etc/azurelinux3s4
# Startup permits the one Unix connect. The worker must seal connect, flagged
# sends, socket/FD acquisition and process creation BEFORE forwarding any bytes.
SystemCallFilter=~recvmsg recvmmsg pidfd_getfd
"""
    listener = f"""[Unit]
Description=Azure Linux 3 HTTP ingress candidate

[Socket]
ListenStream=0.0.0.0:80
ListenStream=[::]:80
BindIPv6Only=ipv6-only
Accept=yes
MaxConnections=32
Backlog=256

[Install]
WantedBy=sockets.target
"""
    nginx = f"""daemon on;
master_process on;
worker_processes 1;
pid {RUNTIME}/nginx.pid;
error_log stderr warn;
events {{
    worker_connections 512;
}}
http {{
    access_log /dev/stdout;
    server_tokens off;
    default_type application/octet-stream;
    sendfile on;
    autoindex off;
    disable_symlinks on;
    client_max_body_size 1m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 30s;
    keepalive_timeout 15s;
    client_body_temp_path {RUNTIME}/client-body;
    proxy_temp_path {RUNTIME}/proxy;
    fastcgi_temp_path {RUNTIME}/fastcgi;
    uwsgi_temp_path {RUNTIME}/uwsgi;
    scgi_temp_path {RUNTIME}/scgi;
    server {{
        listen unix:{RUNTIME}/http.sock;
        server_name _;
        root {CONTENT};
        location / {{
            try_files $uri $uri/ =404;
        }}
    }}
}}
"""
    return {
        "systemd/" + BACKEND + ".service": backend,
        "systemd/" + PROXY + "@.service": proxy,
        "systemd/" + PROXY + ".socket": listener,
        "nginx/nginx.conf": nginx,
        "sysusers/azurelinux3s4-web.conf": "g " + GROUP + " -\n",
        "systemd/azurelinux3s4-web.slice": """[Unit]
Description=Azure Linux 3 web aggregate resource candidate

[Slice]
MemoryMax=512M
MemorySwapMax=0
TasksMax=128
CPUQuota=100%
""",
        # RELAY_SOURCE is supplied by the explicit assembly before this payload.
        # Source-level tests supply the same maintained bytes, never an env value.
        "lib/web-relay.py": RELAY_SOURCE,
    }


def bundle():
    candidates = []
    for name, content in sorted(files().items()):
        data = content.encode("utf-8")
        candidates.append({"file": name, "mode": "0644", "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest(), "content": content})
    # Emission proves candidate bytes only. Never equate a generated directive
    # with its actual enforcement, a listener, TLS, or completed host isolation.
    return {
        "schema": 1, "profile": "static-http-unix-backend", "files": candidates,
        "authority": {name: False for name in (
            "files_installed", "accounts_created", "packages_installed", "units_activated",
            "kernel_enforcement_verified", "nginx_configuration_tested", "proxy_egress_restricted",
            "inherited_inet_sockets_restricted", "lan_containment_verified", "tls_ready", "server_ready")},
        "prerequisites": [
            "Fresh authenticated nginx/systemd runtime and supported native x86_64/aarch64 ABI.",
            "Root-owned protected configuration/content and a checked dedicated shared group.",
            "Conflict-safe durable installation, actual parser tests and boot/repair ownership.",
            "Positive network namespace/seccomp/filesystem/capability enforcement challenges.",
            "Independent proxy egress protection covering inherited TCP sockets, with positive refusal challenges.",
            "Trusted Python/libseccomp/close_range and per-connection worker sealing BEFORE forwarding, including connect/Fast Open/FD-acquisition refusals and same-connection byte/half-close proof.",
            "Only the accepted stdin TCP socket and checked Unix/non-IP logging descriptors may be inherited; verify aggregate slice/MaxConnections and per-worker limits.",
            "Current MAC, content/runtime access and capacity policy; native nginx/proxy lifecycle proof.",
            "HTTPS certificate provisioning/renewal, listener/firewall policy and client identity/rate controls.",
        ],
        "limits": [
            "Candidate HTTP files only; generation does not install, activate or inspect the host.",
            "The worker retains an inherited IP connection; socket creation restrictions alone do not stop reconnects. No activation or native Azure worker/unit enforcement is certified by emission.",
            "The worker connects to its fixed Unix backend once, then denies connection setup/flagged sends and forwards through bounded read/write queues. Trusted startup/import/native libraries and the checked backend peer remain assumptions.",
            "No nft_socket feature is assumed: Azure Linux3 x86 source config disables it. Host-wide firewall and non-web egress policy remain separate unfinished components.",
            "Pathname Unix sockets remain reachable across private network namespaces; privileged IPC policy needs verification.",
            "Static content only; no upstream, DNS, reverse proxy, .NET application or certificate lifecycle is configured.",
            "The byte-forwarding proxy does not preserve a trusted original client address at nginx.",
            "Responses to accepted clients remain possible; compromised host/root/kernel protection is not claimed.",
        ],
    }


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("no policy overrides are accepted")
        resource.setrlimit(resource.RLIMIT_CPU, (10, 15))
        resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = json.dumps(bundle(), sort_keys=True, separators=(",", ":")) + "\n"
        sys.stdout.write(result)
    except (OSError, ValueError, MemoryError) as error:
        print("Web policy emission failed: " + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Admit Email's declared gateway paths and admin networks before inactive units."""


EMAIL_GATEWAY_STATE = '/var/lib/mk8.email/gateway'
EMAIL_ADMIN_FIELDS = ('AllowedNetworks', 'DataProtectionKeyPath', 'AuditLogPath', 'HealthStatusPath', 'SessionMinutes')
EMAIL_ADMIN_PATHS = {'DataProtectionKeyPath': EMAIL_GATEWAY_STATE + '/data-protection',
                     'AuditLogPath': EMAIL_GATEWAY_STATE + '/audit/admin.jsonl',
                     'HealthStatusPath': EMAIL_GATEWAY_STATE + '/health/status.json'}


def email_role_observe(captured, plan):
    worker, gateway = (release_json(captured[role + '.json']) for role in ('worker', 'gateway'))
    if type(worker) is not dict or type(gateway) is not dict or 'Admin' in worker:
        raise ValueError('Email gateway-only admin declaration required')
    admin = gateway.get('Admin')
    if type(admin) is not dict or admin.keys() - set(EMAIL_ADMIN_FIELDS):
        raise ValueError('canonical Email gateway admin record required')
    if any(admin.get(field) != path for field, path in EMAIL_ADMIN_PATHS.items()):
        raise ValueError('Email gateway-owned persistent paths required')
    networks = admin.get('AllowedNetworks')
    # Exact declarations only. This does not attest assignment, original-client
    # locality, forwarded-header policy, a proxy, or actual request enforcement.
    prefixes = [row['prefix'] for row in plan['admin']]
    if type(networks) is not list or networks not in (prefixes[:1], prefixes):
        raise ValueError('complete canonical Email admin network declarations required')
    minutes = admin.get('SessionMinutes', 30)
    if type(minutes) is not int or not 5 <= minutes <= 480:
        raise ValueError('bounded Email gateway admin session declaration required')
    # No separate receipt: original configuration hashes and whole unit bytes
    # retain these declarations. Accounts/directories remain unprovisioned.

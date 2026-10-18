"""Disconnected exact owned-configuration retirement/reinstallation libraries."""


CONFIG_ROLLBACK_LIMITS = [
    'Disconnected library only; no CLI/default invocation or operational authorization. Native consumers, stopped-context and complete existing configuration precedence remain unproved.',
    'Only the five exact owned configuration names return to absence. No previous configuration, firewall ruleset, SSH/PG loaded state, account, database or service state is restored.',
    'Fresh complete original planning and all destination/owner/marker admissions precede retirement and repeat under the configuration-only lock. Exact owned 0600 prefixes may be retired.',
    'Complete marker synchronization precedes every unlink, including a retained-marker retry. Installation ownership remains until all selected targets are absent and parents synchronized.',
    'Interrupted retirement preserves ownership/marker/remainder; foreign or changed late bytes refuse without early deletion. Open files and native loaded configuration may outlive unlink.',
    'The unchanged installer refuses a retained rollback marker. The separate exact reinstallation transition is required before writing again.',
    'Sequential observations and file retirement are not atomic, hostile-root/ABA safe, physical power-loss durable or hard blocked-IO progress guarantees.',
]
CONFIG_REINSTALL_LIMITS = [
    'Disconnected library only; no CLI/default or native activation. This transitions exact owned configuration files, not effective host configuration or services.',
    'A complete marker requires every target absent. Exact ownership is synchronized before marker retirement; partial/foreign records refuse without recovery or deletion.',
    'After checked closes and unlock, the fixed configuration installer reconstructs all five original payloads and reacquires the same configuration-only lock. Changed source/plan cannot reuse ownership.',
    'Failures may leave both records, ownership alone or original 0600 prefixes. The transition/writer gap is sequential and not an atomic transaction or concurrent-root guarantee.',
    'Marker-absent continuation proves no prior operational rollback. No previous versions, effective firewall/SSH/PG state, accounts, databases, physical durability or boot lifecycle is restored.',
]


def configuration_rollback_plan(data, ssh_producer):
    digest, owner, rows = configuration_installation_plan(data, ssh_producer)
    marker = publication_encoded({'format': 'azurelinux3s4-configuration-file-rollback-v1',
                                  'publication_sha256': digest,
                                  'installation_record': {'bytes': len(owner),
                                                          'sha256': dep_hash.sha256(owner).hexdigest()},
                                  'files': len(rows), 'restored_destination_state': 'absent',
                                  'activation_authorized': False})
    return digest, owner, rows, marker


def configuration_rollback(data, ssh_producer):
    return rollback_apply(data, ssh_producer, configuration=True)


def configuration_reinstallation(data, ssh_producer):
    return reinstallation_apply(data, ssh_producer, configuration=True)

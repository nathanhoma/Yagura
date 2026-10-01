"""Reference investigations available to model reasoning and human operators."""


def reference(identifier, title, command, purpose, tool, stage):
    return dict(id=identifier, title=title, command=command, when=purpose,
                tool=tool, stage=stage, executable=False)


REFERENCE_CHECKS = [
    reference('web-fuzz', 'Discover web routes', 'ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 -fc 404 -rate 2 -t 1 -maxtime 30', 'Discover routes; redirects and 403 responses are clues, not proof of exposure. Compare soft-404 responses.', 'ffuf', 'recon'),
    reference('web-config', 'Inspect an exposed web configuration', 'curl --max-time 5 {url}/{configuration_path}', 'Collect a selected configuration response and verify its content, not only its status.', 'curl', 'recon'),
    reference('git-source', 'Collect exposed Git source', 'git-dumper {url}/.git/ {destination}', 'Collect source after confirming Git metadata exposure; import relevant excerpts as evidence.', 'git-dumper', 'recon'),
    reference('source-review', 'Review configuration in collected source', 'grep -RniE "(DB_HOST|DB_USER|DB_PASSWORD|mysql|password|sqlite)" {source_directory}', 'Find configuration and credential references; review and redact secrets before importing.', 'grep', 'offline'),
    reference('backup-list', 'List application backups', 'ls -la {backup_directory}', 'Record available backups from an established target session.', 'ls', 'post-access'),
    reference('backup-read', 'Read a selected backup configuration', 'cat {backup_configuration}', 'Collect configuration from a selected backup; retain date and source context.', 'cat', 'post-access'),
    reference('backup-diff', 'Compare backup configurations', 'diff -u {older_configuration} {newer_configuration}', 'Inspect changes without assuming old credentials remain valid.', 'diff', 'offline'),
    reference('ssh-auth', 'Verify a known SSH identity', 'ssh -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 {user}@{host} id', 'Verify one known credential interactively and capture identity or authentication failure.', 'ssh', 'authentication'),
    reference('process-list', 'Inspect running processes', 'ps aux', 'Record process ownership and command lines in an established session.', 'ps', 'post-access'),
    reference('keepass-version', 'Inspect KeePass version', 'mono {keepass_executable} --version', 'Record version; version alone does not establish memory readability or password recovery.', 'mono', 'post-access'),
    reference('keepass-entry', 'Inspect an accessible KeePass entry', 'keepassxc-cli show {database_path} {entry_name}', 'Inspect an entry using an already available database and unlock material.', 'keepassxc-cli', 'offline'),
    reference('windows-identity', 'Inspect Windows identity', 'whoami /all', 'Record account, groups and privileges in the established session.', 'whoami', 'post-access'),
    reference('support-script', 'Read a support connection script', 'Get-Content -LiteralPath "{script_path}"', 'Inspect the endpoint, configuration and authentication requirements.', 'PowerShell', 'post-access'),
    reference('jea-connect', 'Connect to a known JEA endpoint', 'Enter-PSSession -ComputerName "{host}" -ConfigurationName "{configuration}" -Credential (Get-Credential)', 'Connect interactively with a known account; preserve endpoint and identity context.', 'PowerShell', 'authentication'),
    reference('jea-commands', 'Inspect JEA command availability', 'Get-Command', 'Record commands exposed inside the selected JEA session.', 'PowerShell', 'post-access'),
    reference('routine-metadata', 'Inspect routine task metadata', 'Get-RoutineTask', 'Collect task, runner, manifest and share metadata where this custom command exists.', 'PowerShell', 'post-access'),
    reference('pfx-metadata', 'Inspect PFX certificate metadata', 'Get-PfxData -FilePath "{pfx_path}" -Password (Read-Host -AsSecureString)', 'Inspect certificate metadata with known unlock material without importing into a certificate store.', 'PowerShell', 'offline'),
    reference('signature-status', 'Inspect script signature status', 'Get-AuthenticodeSignature -LiteralPath "{script_path}"', 'Record signature status; a valid signature alone does not establish manifest acceptance.', 'PowerShell', 'offline'),
    reference('routine-result', 'Read routine handoff output', 'Get-Content -LiteralPath "{handoff_path}"', 'Collect existing output and correlate it with submission identity and time.', 'PowerShell', 'post-access'),
    reference('mysql-rights', 'Inspect MySQL identity and file-export policy', "mysql -h {host} -u {user} -p -e 'SELECT USER(), CURRENT_USER(); SHOW GRANTS; SELECT @@secure_file_priv;'", 'Inspect grants and file policy with known credentials. NULL disables file import/export; empty string and directory values have different meanings.', 'mysql', 'authentication'),
    reference('web-process', 'Inspect web process ownership', 'ps -eo user,pid,args', 'Record web/PHP process identity separately from database privileges.', 'ps', 'post-access'),
    reference('document-response', 'Inspect a document parameter response', 'curl --max-time 5 --get {url} --data-urlencode "page={document_name}"', 'Compare selected document responses and content; a page parameter alone does not prove LFI.', 'curl', 'recon'),
    reference('sqlite-schema', 'Inspect a collected SQLite schema', 'sqlite3 -readonly {database_path} .schema', 'Inspect a collected database without modifying it.', 'sqlite3', 'offline'),
    reference('sqlite-users', 'Inspect a known user table', 'sqlite3 -readonly {database_path} "SELECT username, password FROM users;"', 'Use only after schema review confirms these fields; review sensitive output before importing.', 'sqlite3', 'offline'),
]

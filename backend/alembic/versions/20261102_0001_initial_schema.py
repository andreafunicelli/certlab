"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-11-02 09:49:05.384979
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('certificates',
    sa.Column('fingerprint_sha256', sa.String(length=64), nullable=False),
    sa.Column('common_name', sa.String(length=255), nullable=True),
    sa.Column('subject', sa.Text(), nullable=False),
    sa.Column('sans', postgresql.ARRAY(sa.String()), server_default='{}', nullable=False),
    sa.Column('issuer', sa.Text(), nullable=False),
    sa.Column('serial_number', sa.String(length=80), nullable=False),
    sa.Column('public_key_algorithm', sa.String(length=16), nullable=False),
    sa.Column('public_key_size', sa.Integer(), nullable=True),
    sa.Column('public_key_sha256', sa.String(length=64), nullable=False),
    sa.Column('signature_algorithm', sa.String(length=64), nullable=False),
    sa.Column('not_before', postgresql.TIMESTAMP(timezone=True), nullable=False),
    sa.Column('not_after', postgresql.TIMESTAMP(timezone=True), nullable=False),
    sa.Column('is_ca', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('chain_info', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('certificate_type', sa.String(length=16), server_default='leaf', nullable=False),
    sa.Column('discovery_source', sa.String(length=32), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=True),
    sa.Column('tags', postgresql.ARRAY(sa.String()), server_default='{}', nullable=False),
    sa.Column('status', sa.String(length=16), server_default='valid', nullable=False),
    sa.Column('pem', sa.Text(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("certificate_type IN ('leaf', 'intermediate', 'root', 'self_signed')", name=op.f('ck_certificates_certificate_type')),
    sa.CheckConstraint("status IN ('valid', 'expiring', 'critical', 'expired', 'error')", name=op.f('ck_certificates_status')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_certificates')),
    sa.UniqueConstraint('fingerprint_sha256', name=op.f('uq_certificates_fingerprint_sha256'))
    )
    op.create_index(op.f('ix_certificates_common_name'), 'certificates', ['common_name'], unique=False)
    op.create_index(op.f('ix_certificates_not_after'), 'certificates', ['not_after'], unique=False)
    op.create_index(op.f('ix_certificates_public_key_sha256'), 'certificates', ['public_key_sha256'], unique=False)
    op.create_table('encrypted_artifacts',
    sa.Column('purpose', sa.String(length=64), nullable=False),
    sa.Column('key_id', sa.String(length=32), nullable=False),
    sa.Column('wrapped_dek', sa.LargeBinary(), nullable=False),
    sa.Column('nonce', sa.LargeBinary(), nullable=False),
    sa.Column('sha256_plain', sa.String(length=64), nullable=False),
    sa.Column('size', sa.BigInteger(), nullable=False),
    sa.Column('filename', sa.String(length=128), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deleted_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_encrypted_artifacts'))
    )
    op.create_index('ix_encrypted_artifacts_purpose', 'encrypted_artifacts', ['purpose'], unique=False)
    op.create_table('environments',
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('is_production', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('requires_approval', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_environments')),
    sa.UniqueConstraint('name', name=op.f('uq_environments_name'))
    )
    op.create_table('notification_channels',
    sa.Column('type', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('secret_encrypted', sa.Text(), nullable=True),
    sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("type IN ('smtp', 'webhook')", name=op.f('ck_notification_channels_type')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notification_channels')),
    sa.UniqueConstraint('name', name=op.f('uq_notification_channels_name'))
    )
    op.create_table('roles',
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_roles')),
    sa.UniqueConstraint('name', name=op.f('uq_roles_name'))
    )
    op.create_table('users',
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('display_name', sa.String(length=128), nullable=False),
    sa.Column('auth_provider', sa.String(length=16), server_default='local', nullable=False),
    sa.Column('oidc_subject', sa.String(length=255), nullable=True),
    sa.Column('password_hash', sa.Text(), nullable=True),
    sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('mfa_enabled', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('mfa_secret_encrypted', sa.Text(), nullable=True),
    sa.Column('failed_login_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('locked_until', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('password_changed_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('last_login_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("auth_provider IN ('local', 'oidc')", name=op.f('ck_users_auth_provider')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name='uq_users_email'),
    sa.UniqueConstraint('username', name='uq_users_username')
    )
    op.create_index('uq_users_oidc_subject', 'users', ['oidc_subject'], unique=True, postgresql_where='oidc_subject IS NOT NULL')
    op.create_table('app_settings',
    sa.Column('section', sa.String(length=32), nullable=False),
    sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('version', sa.Integer(), server_default='1', nullable=False),
    sa.Column('updated_by', sa.UUID(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], name=op.f('fk_app_settings_updated_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_app_settings')),
    sa.UniqueConstraint('section', name=op.f('uq_app_settings_section'))
    )
    op.create_table('audit_events',
    sa.Column('ts', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('actor_user_id', sa.UUID(), nullable=True),
    sa.Column('actor_name', sa.String(length=128), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('resource_type', sa.String(length=48), nullable=True),
    sa.Column('resource_id', sa.String(length=64), nullable=True),
    sa.Column('before', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('after', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=300), nullable=True),
    sa.Column('correlation_id', sa.String(length=64), nullable=True),
    sa.Column('outcome', sa.String(length=8), server_default='success', nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("outcome IN ('success', 'failure', 'denied')", name=op.f('ck_audit_events_outcome')),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], name=op.f('fk_audit_events_actor_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    op.create_index(op.f('ix_audit_events_action'), 'audit_events', ['action'], unique=False)
    op.create_index(op.f('ix_audit_events_actor_user_id'), 'audit_events', ['actor_user_id'], unique=False)
    op.create_index('ix_audit_events_resource', 'audit_events', ['resource_type', 'resource_id'], unique=False)
    op.create_index(op.f('ix_audit_events_ts'), 'audit_events', ['ts'], unique=False)
    op.create_table('certificate_versions',
    sa.Column('certificate_id', sa.UUID(), nullable=True),
    sa.Column('fingerprint_sha256', sa.String(length=64), nullable=True),
    sa.Column('leaf_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('cert_artifact_id', sa.UUID(), nullable=True),
    sa.Column('key_artifact_id', sa.UUID(), nullable=True),
    sa.Column('chain_artifact_id', sa.UUID(), nullable=True),
    sa.Column('uploaded_by', sa.UUID(), nullable=True),
    sa.Column('validation_status', sa.String(length=16), server_default='pending', nullable=False),
    sa.Column('findings', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
    sa.Column('status', sa.String(length=16), server_default='uploaded', nullable=False),
    sa.Column('reuses_existing_key', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('uploaded', 'validated', 'deployed', 'superseded', 'rejected')", name=op.f('ck_certificate_versions_status')),
    sa.CheckConstraint("validation_status IN ('pending', 'valid', 'warnings', 'invalid')", name=op.f('ck_certificate_versions_validation_status')),
    sa.ForeignKeyConstraint(['cert_artifact_id'], ['encrypted_artifacts.id'], name=op.f('fk_certificate_versions_cert_artifact_id_encrypted_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], name=op.f('fk_certificate_versions_certificate_id_certificates'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['chain_artifact_id'], ['encrypted_artifacts.id'], name=op.f('fk_certificate_versions_chain_artifact_id_encrypted_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['key_artifact_id'], ['encrypted_artifacts.id'], name=op.f('fk_certificate_versions_key_artifact_id_encrypted_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], name=op.f('fk_certificate_versions_uploaded_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_certificate_versions'))
    )
    op.create_index(op.f('ix_certificate_versions_certificate_id'), 'certificate_versions', ['certificate_id'], unique=False)
    op.create_index(op.f('ix_certificate_versions_fingerprint_sha256'), 'certificate_versions', ['fingerprint_sha256'], unique=False)
    op.create_table('credentials',
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('type', sa.String(length=32), server_default='ssh_private_key', nullable=False),
    sa.Column('encrypted_artifact_id', sa.UUID(), nullable=False),
    sa.Column('passphrase_encrypted', sa.Text(), nullable=True),
    sa.Column('public_key', sa.Text(), nullable=False),
    sa.Column('fingerprint_sha256', sa.String(length=80), nullable=False),
    sa.Column('key_algorithm', sa.String(length=32), nullable=True),
    sa.Column('rotated_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('created_by', sa.UUID(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("type IN ('ssh_private_key')", name=op.f('ck_credentials_type')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_credentials_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['encrypted_artifact_id'], ['encrypted_artifacts.id'], name=op.f('fk_credentials_encrypted_artifact_id_encrypted_artifacts'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_credentials')),
    sa.UniqueConstraint('name', name=op.f('uq_credentials_name'))
    )
    op.create_table('notification_rules',
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('channel_id', sa.UUID(), nullable=False),
    sa.Column('min_severity', sa.String(length=8), server_default='info', nullable=False),
    sa.Column('filters', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('reminder_interval_hours', sa.Integer(), nullable=True),
    sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("min_severity IN ('info', 'warning', 'high', 'critical')", name=op.f('ck_notification_rules_min_severity')),
    sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id'], name=op.f('fk_notification_rules_channel_id_notification_channels'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notification_rules'))
    )
    op.create_index(op.f('ix_notification_rules_channel_id'), 'notification_rules', ['channel_id'], unique=False)
    op.create_index(op.f('ix_notification_rules_event_type'), 'notification_rules', ['event_type'], unique=False)
    op.create_table('sessions',
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', postgresql.TIMESTAMP(timezone=True), nullable=False),
    sa.Column('last_seen_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('reauth_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('revoked_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=300), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sessions')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_sessions_token_hash'))
    )
    op.create_index('ix_sessions_expires_at', 'sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)
    op.create_table('user_roles',
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('role_id', sa.UUID(), nullable=False),
    sa.Column('assigned_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_user_roles_role_id_roles'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_roles_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'role_id', name=op.f('pk_user_roles'))
    )
    op.create_table('deployment_jobs',
    sa.Column('version_id', sa.UUID(), nullable=False),
    sa.Column('initiated_by', sa.UUID(), nullable=True),
    sa.Column('strategy', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('dry_run_plan', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('status', sa.String(length=32), server_default='pending', nullable=False),
    sa.Column('approval_required', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('approved_by', sa.UUID(), nullable=True),
    sa.Column('approved_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('idempotency_key', sa.String(length=128), nullable=True),
    sa.Column('started_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('finished_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('rollback_status', sa.String(length=32), nullable=True),
    sa.Column('error_summary', sa.Text(), nullable=True),
    sa.Column('cancel_requested', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('acknowledged_warnings', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'preflight', 'awaiting_approval', 'backing_up', 'staging', 'validating', 'activating', 'reloading', 'verifying', 'completed', 'failed', 'rolling_back', 'rolled_back', 'manual_intervention_required', 'cancelled', 'partially_failed')", name=op.f('ck_deployment_jobs_status')),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], name=op.f('fk_deployment_jobs_approved_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['initiated_by'], ['users.id'], name=op.f('fk_deployment_jobs_initiated_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['version_id'], ['certificate_versions.id'], name=op.f('fk_deployment_jobs_version_id_certificate_versions'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_deployment_jobs')),
    sa.UniqueConstraint('idempotency_key', name=op.f('uq_deployment_jobs_idempotency_key'))
    )
    op.create_index(op.f('ix_deployment_jobs_status'), 'deployment_jobs', ['status'], unique=False)
    op.create_index(op.f('ix_deployment_jobs_version_id'), 'deployment_jobs', ['version_id'], unique=False)
    op.create_table('notification_deliveries',
    sa.Column('rule_id', sa.UUID(), nullable=True),
    sa.Column('channel_id', sa.UUID(), nullable=True),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('dedupe_key', sa.String(length=255), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('status', sa.String(length=16), server_default='pending', nullable=False),
    sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('sent_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'sent', 'failed', 'skipped')", name=op.f('ck_notification_deliveries_status')),
    sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id'], name=op.f('fk_notification_deliveries_channel_id_notification_channels'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['rule_id'], ['notification_rules.id'], name=op.f('fk_notification_deliveries_rule_id_notification_rules'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notification_deliveries'))
    )
    op.create_index(op.f('ix_notification_deliveries_channel_id'), 'notification_deliveries', ['channel_id'], unique=False)
    op.create_index('ix_notification_deliveries_dedupe_key', 'notification_deliveries', ['dedupe_key'], unique=False)
    op.create_table('servers',
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('address', sa.String(length=64), nullable=True),
    sa.Column('ssh_port', sa.Integer(), server_default='22', nullable=False),
    sa.Column('ssh_username', sa.String(length=64), nullable=False),
    sa.Column('credential_id', sa.UUID(), nullable=True),
    sa.Column('bastion_server_id', sa.UUID(), nullable=True),
    sa.Column('privilege_mode', sa.String(length=16), server_default='helper-sudo', nullable=False),
    sa.Column('os_family', sa.String(length=32), nullable=True),
    sa.Column('os_version', sa.String(length=64), nullable=True),
    sa.Column('os_pretty', sa.String(length=128), nullable=True),
    sa.Column('environment', sa.String(length=64), nullable=False),
    sa.Column('tags', postgresql.ARRAY(sa.String()), server_default='{}', nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('connection_status', sa.String(length=24), server_default='unknown', nullable=False),
    sa.Column('host_key_type', sa.String(length=32), nullable=True),
    sa.Column('host_public_key', sa.Text(), nullable=True),
    sa.Column('host_key_fingerprint', sa.String(length=80), nullable=True),
    sa.Column('host_key_enrolled_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('host_key_enrolled_by', sa.UUID(), nullable=True),
    sa.Column('last_connected_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('last_discovery_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('last_discovery_status', sa.String(length=24), nullable=True),
    sa.Column('discovery_error', sa.Text(), nullable=True),
    sa.Column('detected_services', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("connection_status IN ('unknown', 'connected', 'offline', 'auth_error', 'host_key_mismatch', 'host_key_unknown', 'error')", name=op.f('ck_servers_connection_status')),
    sa.CheckConstraint("privilege_mode IN ('helper-sudo', 'none')", name=op.f('ck_servers_privilege_mode')),
    sa.CheckConstraint('ssh_port BETWEEN 1 AND 65535', name=op.f('ck_servers_ssh_port_range')),
    sa.ForeignKeyConstraint(['bastion_server_id'], ['servers.id'], name=op.f('fk_servers_bastion_server_id_servers'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['credential_id'], ['credentials.id'], name=op.f('fk_servers_credential_id_credentials'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['environment'], ['environments.name'], name=op.f('fk_servers_environment_environments'), onupdate='CASCADE', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['host_key_enrolled_by'], ['users.id'], name=op.f('fk_servers_host_key_enrolled_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_servers')),
    sa.UniqueConstraint('name', name=op.f('uq_servers_name'))
    )
    op.create_index('ix_servers_connection_status', 'servers', ['connection_status'], unique=False)
    op.create_index(op.f('ix_servers_credential_id'), 'servers', ['credential_id'], unique=False)
    op.create_index(op.f('ix_servers_environment'), 'servers', ['environment'], unique=False)
    op.create_table('certificate_installations',
    sa.Column('certificate_id', sa.UUID(), nullable=True),
    sa.Column('server_id', sa.UUID(), nullable=False),
    sa.Column('service_type', sa.String(length=16), nullable=False),
    sa.Column('service_identifier', sa.String(length=255), nullable=True),
    sa.Column('cert_path', sa.Text(), nullable=True),
    sa.Column('key_path', sa.Text(), nullable=True),
    sa.Column('chain_path', sa.Text(), nullable=True),
    sa.Column('fullchain_path', sa.Text(), nullable=True),
    sa.Column('is_combined_pem', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('listen_port', sa.Integer(), nullable=True),
    sa.Column('config_file', sa.Text(), nullable=True),
    sa.Column('vhost', sa.String(length=255), nullable=True),
    sa.Column('server_names', postgresql.ARRAY(sa.String()), server_default='{}', nullable=False),
    sa.Column('last_observed_fingerprint', sa.String(length=64), nullable=True),
    sa.Column('last_observed_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('last_deployment_id', sa.UUID(), nullable=True),
    sa.Column('drift_status', sa.String(length=16), server_default='unknown', nullable=False),
    sa.Column('classification', sa.String(length=24), server_default='unmanaged', nullable=False),
    sa.Column('discovery_confidence', sa.Double(), server_default='1.0', nullable=False),
    sa.Column('managed_by_certbot', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('file_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('verify_host', sa.String(length=255), nullable=True),
    sa.Column('verify_port', sa.Integer(), nullable=True),
    sa.Column('verify_sni', sa.String(length=255), nullable=True),
    sa.Column('last_verification', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('missing_since', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('identity_key', sa.String(length=64), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("classification IN ('managed', 'unmanaged', 'requires_mapping', 'unsupported', 'unreadable', 'error')", name=op.f('ck_certificate_installations_classification')),
    sa.CheckConstraint("drift_status IN ('in_sync', 'drifted', 'missing', 'unknown')", name=op.f('ck_certificate_installations_drift_status')),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], name=op.f('fk_certificate_installations_certificate_id_certificates'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['last_deployment_id'], ['deployment_jobs.id'], name='fk_installations_last_deployment', ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['server_id'], ['servers.id'], name=op.f('fk_certificate_installations_server_id_servers'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_certificate_installations')),
    sa.UniqueConstraint('server_id', 'identity_key', name='uq_installations_server_identity')
    )
    op.create_index(op.f('ix_certificate_installations_certificate_id'), 'certificate_installations', ['certificate_id'], unique=False)
    op.create_index(op.f('ix_certificate_installations_server_id'), 'certificate_installations', ['server_id'], unique=False)
    op.create_index('ix_installations_classification', 'certificate_installations', ['classification'], unique=False)
    op.create_index('ix_installations_drift', 'certificate_installations', ['drift_status'], unique=False)
    op.create_table('discovery_jobs',
    sa.Column('server_id', sa.UUID(), nullable=False),
    sa.Column('requested_by', sa.UUID(), nullable=True),
    sa.Column('status', sa.String(length=16), server_default='pending', nullable=False),
    sa.Column('started_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('finished_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('stats', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'running', 'completed', 'failed', 'partial', 'cancelled')", name=op.f('ck_discovery_jobs_status')),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_discovery_jobs_requested_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['server_id'], ['servers.id'], name=op.f('fk_discovery_jobs_server_id_servers'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_discovery_jobs'))
    )
    op.create_index(op.f('ix_discovery_jobs_server_id'), 'discovery_jobs', ['server_id'], unique=False)
    op.create_table('backups',
    sa.Column('server_id', sa.UUID(), nullable=False),
    sa.Column('installation_id', sa.UUID(), nullable=True),
    sa.Column('deployment_target_id', sa.UUID(), nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('manifest', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('integrity_sha256', sa.String(length=64), nullable=True),
    sa.Column('verified', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('retention_until', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('restore_status', sa.String(length=16), server_default='none', nullable=False),
    sa.Column('restored_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("restore_status IN ('none', 'in_progress', 'restored', 'failed')", name=op.f('ck_backups_restore_status')),
    sa.ForeignKeyConstraint(['installation_id'], ['certificate_installations.id'], name=op.f('fk_backups_installation_id_certificate_installations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['server_id'], ['servers.id'], name=op.f('fk_backups_server_id_servers'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_backups'))
    )
    op.create_index(op.f('ix_backups_installation_id'), 'backups', ['installation_id'], unique=False)
    op.create_index(op.f('ix_backups_retention_until'), 'backups', ['retention_until'], unique=False)
    op.create_index(op.f('ix_backups_server_id'), 'backups', ['server_id'], unique=False)
    op.create_table('deployment_targets',
    sa.Column('job_id', sa.UUID(), nullable=False),
    sa.Column('installation_id', sa.UUID(), nullable=True),
    sa.Column('server_id', sa.UUID(), nullable=False),
    sa.Column('batch_index', sa.Integer(), server_default='0', nullable=False),
    sa.Column('is_canary', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('status', sa.String(length=32), server_default='pending', nullable=False),
    sa.Column('current_step', sa.String(length=64), nullable=True),
    sa.Column('steps', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
    sa.Column('previous_fingerprint', sa.String(length=64), nullable=True),
    sa.Column('new_fingerprint', sa.String(length=64), nullable=True),
    sa.Column('backup_id', sa.UUID(), nullable=True),
    sa.Column('rollback_attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('verification', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('error_code', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('log', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'preflight', 'awaiting_approval', 'backing_up', 'staging', 'validating', 'activating', 'reloading', 'verifying', 'completed', 'failed', 'rolling_back', 'rolled_back', 'manual_intervention_required', 'cancelled', 'partially_failed')", name=op.f('ck_deployment_targets_status')),
    sa.ForeignKeyConstraint(['backup_id'], ['backups.id'], name='fk_targets_backup', ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['installation_id'], ['certificate_installations.id'], name=op.f('fk_deployment_targets_installation_id_certificate_installations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['job_id'], ['deployment_jobs.id'], name=op.f('fk_deployment_targets_job_id_deployment_jobs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['server_id'], ['servers.id'], name=op.f('fk_deployment_targets_server_id_servers'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_deployment_targets'))
    )
    op.create_index(op.f('ix_deployment_targets_installation_id'), 'deployment_targets', ['installation_id'], unique=False)
    op.create_index(op.f('ix_deployment_targets_job_id'), 'deployment_targets', ['job_id'], unique=False)
    op.create_index(op.f('ix_deployment_targets_server_id'), 'deployment_targets', ['server_id'], unique=False)
    op.create_table('discovery_findings',
    sa.Column('job_id', sa.UUID(), nullable=False),
    sa.Column('path', sa.Text(), nullable=True),
    sa.Column('classification', sa.String(length=24), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['job_id'], ['discovery_jobs.id'], name=op.f('fk_discovery_findings_job_id_discovery_jobs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_discovery_findings'))
    )
    op.create_index(op.f('ix_discovery_findings_job_id'), 'discovery_findings', ['job_id'], unique=False)
    op.create_table('deployment_locks',
    sa.Column('resource_key', sa.String(length=512), nullable=False),
    sa.Column('job_id', sa.UUID(), nullable=True),
    sa.Column('target_id', sa.UUID(), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=False),
    sa.Column('acquired_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', postgresql.TIMESTAMP(timezone=True), nullable=False),
    sa.Column('heartbeat_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['job_id'], ['deployment_jobs.id'], name=op.f('fk_deployment_locks_job_id_deployment_jobs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_id'], ['deployment_targets.id'], name=op.f('fk_deployment_locks_target_id_deployment_targets'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_deployment_locks')),
    sa.UniqueConstraint('resource_key', name=op.f('uq_deployment_locks_resource_key'))
    )
    op.create_index(op.f('ix_deployment_locks_expires_at'), 'deployment_locks', ['expires_at'], unique=False)
    op.create_index(op.f('ix_deployment_locks_job_id'), 'deployment_locks', ['job_id'], unique=False)

    # backups <-> deployment_targets is a cycle: this FK is added after both tables exist
    op.create_foreign_key('fk_backups_target', 'backups', 'deployment_targets', ['deployment_target_id'], ['id'],
                          ondelete='SET NULL')

    _seed()


def _seed() -> None:
    """Reference data: roles, default environments and default settings sections."""
    import json
    import uuid

    bind = op.get_bind()
    roles = [
        ("admin", "Full administrative access"),
        ("operator", "Run discovery, upload certificate versions and execute deployments"),
        ("viewer", "Read-only access"),
    ]
    for name, desc in roles:
        bind.execute(sa.text("INSERT INTO roles (id, name, description) VALUES (:id, :n, :d)"),
                     {"id": uuid.uuid4(), "n": name, "d": desc})
    envs = [
        ("Production", "Production systems", True, True),
        ("Staging", "Pre-production staging", False, False),
        ("Test", "Test systems", False, False),
        ("Development", "Development systems", False, False),
    ]
    for name, desc, prod, appr in envs:
        bind.execute(
            sa.text("INSERT INTO environments (id, name, description, is_production, requires_approval) "
                    "VALUES (:id, :n, :d, :p, :a)"),
            {"id": uuid.uuid4(), "n": name, "d": desc, "p": prod, "a": appr},
        )
    settings = {
        "general": {"app_name": "Cert Deploy Pro", "timezone": "UTC", "inventory_refresh_minutes": 360,
                    "backup_retention_days": 90},
        "notifications": {"thresholds": {"info": 60, "warning": 30, "high": 14, "critical": 7}},
        "security": {"session_minutes": 480, "require_production_approval": True, "reauth_minutes": 10},
        "ssh": {
            "default_port": 22, "connect_timeout": 10, "command_timeout": 60, "deployment_concurrency": 3,
            "canary": True, "failure_threshold": 1,
            "discovery_roots": ["/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/haproxy", "/etc/ssl",
                                "/etc/pki", "/etc/letsencrypt"],
            "discovery_max_depth": 6, "discovery_max_files": 2000,
            "discovery_exclude": ["/etc/ssl/certs", "/etc/pki/ca-trust", "/usr/share/ca-certificates",
                                  "*/node_modules/*"],
        },
    }
    for section, data in settings.items():
        bind.execute(
            sa.text("INSERT INTO app_settings (id, section, data, version) VALUES (:id, :s, CAST(:d AS jsonb), 1)"),
            {"id": uuid.uuid4(), "s": section, "d": json.dumps(data)},
        )


def downgrade() -> None:
    op.drop_constraint('fk_backups_target', 'backups', type_='foreignkey')
    op.drop_index(op.f('ix_deployment_locks_job_id'), table_name='deployment_locks')
    op.drop_index(op.f('ix_deployment_locks_expires_at'), table_name='deployment_locks')
    op.drop_table('deployment_locks')
    op.drop_index(op.f('ix_discovery_findings_job_id'), table_name='discovery_findings')
    op.drop_table('discovery_findings')
    op.drop_index(op.f('ix_deployment_targets_server_id'), table_name='deployment_targets')
    op.drop_index(op.f('ix_deployment_targets_job_id'), table_name='deployment_targets')
    op.drop_index(op.f('ix_deployment_targets_installation_id'), table_name='deployment_targets')
    op.drop_table('deployment_targets')
    op.drop_index(op.f('ix_backups_server_id'), table_name='backups')
    op.drop_index(op.f('ix_backups_retention_until'), table_name='backups')
    op.drop_index(op.f('ix_backups_installation_id'), table_name='backups')
    op.drop_table('backups')
    op.drop_index(op.f('ix_discovery_jobs_server_id'), table_name='discovery_jobs')
    op.drop_table('discovery_jobs')
    op.drop_index('ix_installations_drift', table_name='certificate_installations')
    op.drop_index('ix_installations_classification', table_name='certificate_installations')
    op.drop_index(op.f('ix_certificate_installations_server_id'), table_name='certificate_installations')
    op.drop_index(op.f('ix_certificate_installations_certificate_id'), table_name='certificate_installations')
    op.drop_table('certificate_installations')
    op.drop_index(op.f('ix_servers_environment'), table_name='servers')
    op.drop_index(op.f('ix_servers_credential_id'), table_name='servers')
    op.drop_index('ix_servers_connection_status', table_name='servers')
    op.drop_table('servers')
    op.drop_index('ix_notification_deliveries_dedupe_key', table_name='notification_deliveries')
    op.drop_index(op.f('ix_notification_deliveries_channel_id'), table_name='notification_deliveries')
    op.drop_table('notification_deliveries')
    op.drop_index(op.f('ix_deployment_jobs_version_id'), table_name='deployment_jobs')
    op.drop_index(op.f('ix_deployment_jobs_status'), table_name='deployment_jobs')
    op.drop_table('deployment_jobs')
    op.drop_table('user_roles')
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_index('ix_sessions_expires_at', table_name='sessions')
    op.drop_table('sessions')
    op.drop_index(op.f('ix_notification_rules_event_type'), table_name='notification_rules')
    op.drop_index(op.f('ix_notification_rules_channel_id'), table_name='notification_rules')
    op.drop_table('notification_rules')
    op.drop_table('credentials')
    op.drop_index(op.f('ix_certificate_versions_fingerprint_sha256'), table_name='certificate_versions')
    op.drop_index(op.f('ix_certificate_versions_certificate_id'), table_name='certificate_versions')
    op.drop_table('certificate_versions')
    op.drop_index(op.f('ix_audit_events_ts'), table_name='audit_events')
    op.drop_index('ix_audit_events_resource', table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_actor_user_id'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_action'), table_name='audit_events')
    op.drop_table('audit_events')
    op.drop_table('app_settings')
    op.drop_index('uq_users_oidc_subject', table_name='users', postgresql_where='oidc_subject IS NOT NULL')
    op.drop_table('users')
    op.drop_table('roles')
    op.drop_table('notification_channels')
    op.drop_table('environments')
    op.drop_index('ix_encrypted_artifacts_purpose', table_name='encrypted_artifacts')
    op.drop_table('encrypted_artifacts')
    op.drop_index(op.f('ix_certificates_public_key_sha256'), table_name='certificates')
    op.drop_index(op.f('ix_certificates_not_after'), table_name='certificates')
    op.drop_index(op.f('ix_certificates_common_name'), table_name='certificates')
    op.drop_table('certificates')

"""
Portable inline schema upgrades for SQLite (legacy) and PostgreSQL (production).

Runs on every app startup after db.create_all() so upgraded code stays compatible with
databases migrated from older SQLite installs and with unmigrated SQLite environments.
"""
from __future__ import annotations

import logging
from typing import Callable

from sqlalchemy import text

from utils.schema_migrations import (
    add_column_if_missing,
    bool_default_sql,
    datetime_type_sql,
    table_column_names,
    table_exists,
)

log = logging.getLogger(__name__)


def run_inline_schema_upgrades(session, engine, commit: Callable[[], None]) -> None:
    """Apply idempotent column/index migrations. Safe on SQLite and PostgreSQL."""
    if engine is None:
        return

    def _cols(table: str) -> set[str]:
        return table_column_names(engine, table)

    def _dt() -> str:
        return datetime_type_sql(engine)

    def _bool(false: bool = True) -> str:
        return bool_default_sql(engine, false=false)

    def _add(table: str, column: str, spec: str) -> None:
        try:
            add_column_if_missing(session, engine, table, column, spec, commit=commit)
        except Exception as exc:
            session.rollback()
            log.warning('schema upgrade %s.%s: %s', table, column, exc)

    def _exec(sql: str) -> None:
        try:
            session.execute(text(sql))
            commit()
        except Exception as exc:
            session.rollback()
            log.warning('schema upgrade SQL failed (%s): %s', sql[:80], exc)

    # --- yara_rules ---
    if table_exists(engine, 'yara_rules'):
        _add('yara_rules', 'campaign_id', 'INTEGER REFERENCES campaigns(id)')
        _add('yara_rules', 'quality_points', 'INTEGER')
        _add('yara_rules', 'status', "VARCHAR(32) NOT NULL DEFAULT 'approved'")
        _add('yara_rules', 'content_sha256', 'VARCHAR(64)')
        _add('yara_rules', 'original_filename', 'VARCHAR(512)')
        for col, spec in (
            ('rejected_at', _dt()),
            ('rejected_by', 'VARCHAR(255)'),
            ('rejection_reason', 'TEXT'),
            ('rejection_seen_at', _dt()),
        ):
            _add('yara_rules', col, spec)
        _exec('CREATE INDEX IF NOT EXISTS ix_yara_rules_content_sha256 ON yara_rules(content_sha256)')

    # --- iocs ---
    if table_exists(engine, 'iocs'):
        _add('iocs', 'tags', "TEXT DEFAULT '[]'")
        _add('iocs', 'submission_method', "VARCHAR(16) DEFAULT 'single'")
        for col, spec in (
            ('country_code', 'VARCHAR(8)'),
            ('tld', 'VARCHAR(32)'),
            ('email_domain', 'VARCHAR(255)'),
            ('rare_find_type', 'VARCHAR(32)'),
        ):
            _add('iocs', col, spec)
        _add('iocs', 'revoked', f'BOOLEAN NOT NULL DEFAULT {_bool()}')
        _add('iocs', 'revoked_at', _dt())
        _add('iocs', 'modified_at', _dt())
        _add('iocs', 'pending_approval', f'BOOLEAN NOT NULL DEFAULT {_bool()}')
        _add('iocs', 'user_id', 'INTEGER REFERENCES users(id)')
        try:
            _exec('UPDATE iocs SET modified_at = created_at WHERE modified_at IS NULL')
        except Exception:
            session.rollback()
        _exec('CREATE INDEX IF NOT EXISTS ix_iocs_revoked ON iocs(revoked)')
        _exec('CREATE INDEX IF NOT EXISTS ix_iocs_modified_at ON iocs(modified_at)')
        _exec('CREATE INDEX IF NOT EXISTS ix_iocs_pending_approval ON iocs(pending_approval)')

    # --- feed / downstream ---
    if table_exists(engine, 'feed_source_last_seen'):
        _add('feed_source_last_seen', 'last_status_code', 'INTEGER')
        _add('feed_source_last_seen', 'last_ok', 'BOOLEAN')

    if table_exists(engine, 'downstream_systems'):
        _add('downstream_systems', 'is_custom_vendor', f'BOOLEAN NOT NULL DEFAULT {_bool()}')
        _add('downstream_systems', 'custom_vendor_label', 'VARCHAR(255)')
        _add('downstream_systems', 'custom_icon_path', 'VARCHAR(512)')
        _add('downstream_systems', 'last_yara_feed_correlated_at', _dt())

    if table_exists(engine, 'ioc_downstream_events'):
        _add('ioc_downstream_events', 'is_active', f'BOOLEAN NOT NULL DEFAULT {_bool(false=False)}')

    # --- users / profiles ---
    if table_exists(engine, 'users'):
        _add('users', 'last_login_at', _dt())
        _add('users', 'must_change_password', f'BOOLEAN NOT NULL DEFAULT {_bool()}')
        _add('users', 'ldap_environment', "VARCHAR(128) NOT NULL DEFAULT ''")
        try:
            if 'ldap_environment' in _cols('users'):
                _exec("UPDATE users SET ldap_environment = '' WHERE ldap_environment IS NULL")
                _exec(
                    "UPDATE users SET ldap_environment = 'Default' "
                    "WHERE source = 'ldap' AND (ldap_environment IS NULL OR ldap_environment = '')"
                )
        except Exception:
            session.rollback()
        # Composite unique (username, ldap_environment) for multi-domain LDAP
        _exec('CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username_ldap_env ON users (username, ldap_environment)')

    if table_exists(engine, 'user_profiles'):
        for col in ('mute_sound', 'ambition_popup_disabled', 'achievement_popup_disabled'):
            _add('user_profiles', col, f'BOOLEAN NOT NULL DEFAULT {_bool()}')

    # --- team_goals / campaigns / champ_scores ---
    if table_exists(engine, 'team_goals'):
        _add('team_goals', 'goal_type', "VARCHAR(32) DEFAULT 'ioc_add' NOT NULL")
        _add('team_goals', 'description', 'TEXT')

    if table_exists(engine, 'campaigns'):
        _add('campaigns', 'dir', "VARCHAR(8) DEFAULT 'ltr'")
        _add('campaigns', 'created_by', 'INTEGER REFERENCES users(id)')
        _add('campaigns', 'reference_image_ext', 'VARCHAR(8)')
        _add('campaigns', 'tags', "TEXT DEFAULT '[]'")

    if table_exists(engine, 'champ_scores'):
        _add('champ_scores', 'streak_days', 'INTEGER NOT NULL DEFAULT 0')

    # --- indexes (both backends) ---
    _exec('CREATE INDEX IF NOT EXISTS ix_ioc_history_type_value ON ioc_history(ioc_type, ioc_value)')
    _exec('CREATE INDEX IF NOT EXISTS ix_ioc_notes_type_value ON ioc_notes(ioc_type, ioc_value)')

    # Backfill user_id on legacy IOC rows after admin exists (see _init_db)

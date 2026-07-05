"""
Portable schema helpers (SQLite legacy + PostgreSQL production).
"""
from __future__ import annotations

import logging

from sqlalchemy import inspect, text

from utils.db_config import is_postgresql_engine, is_sqlite_engine


def table_exists(engine, table_name: str) -> bool:
    try:
        return table_name in inspect(engine).get_table_names()
    except Exception:
        return False


def table_column_names(engine, table_name: str) -> set[str]:
    try:
        if not table_exists(engine, table_name):
            return set()
        return {c['name'] for c in inspect(engine).get_columns(table_name)}
    except Exception:
        return set()


def bool_default_sql(engine, *, false: bool = True) -> str:
    if is_postgresql_engine(engine):
        return 'FALSE' if false else 'TRUE'
    return '0' if false else '1'


def datetime_type_sql(engine) -> str:
    """Portable datetime column type for raw ALTER TABLE statements."""
    return 'TIMESTAMP' if is_postgresql_engine(engine) else 'DATETIME'


def add_column_if_missing(
    session,
    engine,
    table_name: str,
    column_name: str,
    column_spec: str,
    *,
    commit,
) -> bool:
    """
    Add a column when the table exists but the column does not.
    ``column_spec`` is the SQL fragment after the column name (type + constraints).
    Returns True if a column was added.
    """
    if not table_exists(engine, table_name):
        return False
    if column_name in table_column_names(engine, table_name):
        return False
    session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_spec}'))
    commit()
    return True


def enable_sqlite_wal(session) -> None:
    engine = session.bind
    if not engine or not is_sqlite_engine(engine):
        return
    try:
        session.execute(text('PRAGMA journal_mode=WAL'))
        session.commit()
    except Exception:
        session.rollback()


_PG_SERIAL_SEQUENCE_QUERY = text("""
    SELECT
        n.nspname AS schema_name,
        t.relname AS table_name,
        a.attname AS column_name,
        (n.nspname || '.' || c.relname) AS sequence_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_depend d ON d.objid = c.oid AND d.deptype = 'a'
    JOIN pg_class t ON t.oid = d.refobjid
    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid AND NOT a.attisdropped
    WHERE c.relkind = 'S'
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    ORDER BY n.nspname, t.relname
""")


def _pg_engine(session):
    engine = session.bind
    if engine is None:
        try:
            engine = session.get_bind()
        except Exception:
            return None
    return engine


def _pg_qualified_table(schema: str, table_name: str) -> str:
    return f'"{schema}"."{table_name}"'


def _pg_qualified_sequence(schema: str, seq_name: str) -> str:
    return f'"{schema}"."{seq_name}"'


def _pg_ensure_clean_session(session) -> None:
    """Clear aborted transactions so the next statement can run."""
    try:
        session.rollback()
    except Exception:
        pass


def _pg_list_serial_sequences(session) -> list[dict]:
    """All PostgreSQL column-owned sequences (SERIAL / IDENTITY)."""
    engine = _pg_engine(session)
    if not engine or not is_postgresql_engine(engine):
        return []
    return [dict(row) for row in session.execute(_PG_SERIAL_SEQUENCE_QUERY).mappings().all()]


def _pg_sequence_next_id(session, sequence_name: str) -> int | None:
    """Next id that nextval() would return (requires is_called on the sequence relation)."""
    if '.' not in sequence_name:
        return None
    schema, seq_name = sequence_name.rsplit('.', 1)
    fq_seq = _pg_qualified_sequence(schema, seq_name)
    row = session.execute(
        text(f'SELECT last_value, is_called FROM {fq_seq}'),
    ).mappings().first()
    if not row:
        return None
    last_value = int(row['last_value'] or 0)
    return last_value + 1 if bool(row['is_called']) else last_value


def list_postgres_sequence_issues(session, metadata=None) -> list[str]:
    """Return human-readable misaligned sequence descriptions (empty = OK)."""
    engine = _pg_engine(session)
    if not engine or not is_postgresql_engine(engine):
        return []
    _pg_ensure_clean_session(session)
    issues = []
    try:
        rows = _pg_list_serial_sequences(session)
    except Exception as exc:
        _pg_ensure_clean_session(session)
        return [f'could not list PostgreSQL sequences — {exc}']
    for row in rows:
        schema = row['schema_name']
        table = row['table_name']
        column = row['column_name']
        seq = row['sequence_name']
        fq_table = _pg_qualified_table(schema, table)
        try:
            max_id = session.execute(
                text(f'SELECT COALESCE(MAX("{column}"), 0) FROM {fq_table}'),
            ).scalar() or 0
            next_id = _pg_sequence_next_id(session, seq)
            if next_id is None:
                continue
            if int(max_id) >= int(next_id):
                issues.append(
                    f'{schema}.{table}: MAX({column})={max_id} but next sequence id would be {next_id} ({seq})'
                )
        except Exception as exc:
            _pg_ensure_clean_session(session)
            issues.append(f'{schema}.{table}: could not verify sequence — {exc}')
    return issues


def reset_postgres_sequences(
    session,
    table_name: str,
    pk_column: str = 'id',
    schema: str = 'public',
) -> bool:
    """Align one table's PostgreSQL SERIAL/IDENTITY sequence after bulk INSERT with explicit ids."""
    engine = _pg_engine(session)
    if not engine or not is_postgresql_engine(engine):
        return False
    qualified = f'{schema}.{table_name}'
    fq_table = _pg_qualified_table(schema, table_name)
    try:
        seq = session.execute(
            text('SELECT pg_get_serial_sequence(:tbl, :col)'),
            {'tbl': qualified, 'col': pk_column},
        ).scalar()
        if not seq:
            seq = session.execute(
                text('SELECT pg_get_serial_sequence(:tbl, :col)'),
                {'tbl': table_name, 'col': pk_column},
            ).scalar()
        if not seq:
            fallback = f'{schema}.{table_name}_{pk_column}_seq'
            if session.execute(text('SELECT to_regclass(:seq)'), {'seq': fallback}).scalar():
                seq = fallback
        if not seq:
            return False
        session.execute(
            text(
                f'SELECT setval(CAST(:seq AS regclass), '
                f'COALESCE((SELECT MAX("{pk_column}") FROM {fq_table}), 0) + 1, false)'
            ),
            {'seq': seq},
        )
        session.commit()
        return True
    except Exception:
        session.rollback()
        raise


def reset_all_postgres_sequences(session, metadata=None) -> list[str]:
    """
    Reset all PostgreSQL column-owned sequences (via pg_depend catalog).
    Returns list of qualified table names successfully reset.
    """
    engine = _pg_engine(session)
    if not engine or not is_postgresql_engine(engine):
        return []
    _pg_ensure_clean_session(session)
    reset: list[str] = []
    failed: list[str] = []
    seen: set[str] = set()
    for row in _pg_list_serial_sequences(session):
        schema = row['schema_name']
        table = row['table_name']
        column = row['column_name']
        seq = row['sequence_name']
        key = f'{schema}.{table}'
        if key in seen:
            continue
        seen.add(key)
        fq_table = _pg_qualified_table(schema, table)
        try:
            session.execute(
                text(
                    f'SELECT setval(CAST(:seq AS regclass), '
                    f'COALESCE((SELECT MAX("{column}") FROM {fq_table}), 0) + 1, false)'
                ),
                {'seq': seq},
            )
            session.commit()
            reset.append(key)
        except Exception as exc:
            session.rollback()
            failed.append(key)
            logging.warning('PostgreSQL sequence reset failed for %s (%s): %s', key, seq, exc)

    if metadata is not None:
        for table in metadata.sorted_tables:
            if not any(c.name == 'id' for c in table.columns):
                continue
            schema = table.schema or 'public'
            key = f'{schema}.{table.name}'
            if key in seen:
                continue
            try:
                if reset_postgres_sequences(session, table.name, 'id', schema):
                    reset.append(key)
            except Exception as exc:
                session.rollback()
                failed.append(key)
                logging.warning('PostgreSQL sequence reset failed for %s: %s', key, exc)

    if failed:
        logging.warning(
            'PostgreSQL sequence reset incomplete: %d ok, %d failed (%s)',
            len(reset), len(failed), ', '.join(failed[:12]),
        )
    _pg_ensure_clean_session(session)
    remaining = list_postgres_sequence_issues(session, metadata)
    if remaining:
        logging.warning(
            'PostgreSQL sequences still misaligned after reset (%d): %s',
            len(remaining), '; '.join(remaining[:5]),
        )
    return reset


def sql_date_expr(column_ref: str, engine) -> str:
    """Day bucket for raw SQL: SQLite DATE(col), PostgreSQL (col)::date."""
    if engine and is_postgresql_engine(engine):
        return f'({column_ref})::date'
    return f'DATE({column_ref})'


def json_text_field_expr(column_ref: str, json_path: str, engine) -> str:
    """Extract a JSON string field from a TEXT payload column (activity_events.payload)."""
    key = (json_path or '').lstrip('$.')
    if engine and is_postgresql_engine(engine):
        return f"({column_ref}::jsonb->>'{key}')"
    return f"json_extract({column_ref}, '{json_path}')"


def clamp_int_expr(value_expr: str, low: int, high: int, engine) -> str:
    """Clamp numeric SQL expression to [low, high]. PG: LEAST/GREATEST; SQLite: MIN/MAX."""
    if engine and is_postgresql_engine(engine):
        return f'LEAST({high}, GREATEST({low}, {value_expr}))'
    return f'MIN({high}, MAX({low}, {value_expr}))'


def hour_in_clause(column, hours, engine):
    """Filter: column's clock hour is in hours (0-23). PG: extract(hour); SQLite: strftime %H."""
    from sqlalchemy import extract, func

    hours_int = [int(h) for h in hours]
    if engine and is_postgresql_engine(engine):
        return extract('hour', column).in_(hours_int)
    return func.strftime('%H', column).in_([f'{h:02d}' for h in hours_int])


def dow_in_clause(column, days, engine):
    """Filter: day-of-week in days (0=Sunday .. 6=Saturday). PG: extract(dow); SQLite: strftime %w."""
    from sqlalchemy import extract, func

    days_int = [int(d) for d in days]
    if engine and is_postgresql_engine(engine):
        return extract('dow', column).in_(days_int)
    return func.strftime('%w', column).in_([str(d) for d in days_int])

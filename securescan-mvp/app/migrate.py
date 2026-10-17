"""Apply additive SQLite schema migrations for local development."""
import logging

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

logger = logging.getLogger("securescan.migrate")


def auto_migrate_sqlite(engine: Engine, base) -> None:
    if engine.dialect.name != "sqlite":
        return  # Use Alembic for production databases.

    inspector = inspect(engine)

    with engine.begin() as conn:
        for table in base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue

            existing_columns = {col["name"] for col in inspector.get_columns(table.name)}

            for column in table.columns:
                if column.name in existing_columns:
                    continue

                col_type = column.type.compile(engine.dialect)
                default_clause = ""
                if column.default is not None and getattr(column.default, "is_scalar", False):
                    default_val = column.default.arg
                    if isinstance(default_val, bool):
                        default_val = int(default_val)
                    if isinstance(default_val, (int, float)):
                        default_clause = f" DEFAULT {default_val}"
                    elif isinstance(default_val, str):
                        escaped = default_val.replace("'", "''")
                        default_clause = f" DEFAULT '{escaped}'"

                # Existing rows may not have a value for a new NOT NULL column.
                ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}{default_clause}'
                conn.exec_driver_sql(ddl)
                logger.warning("Auto-migration: added column %s.%s", table.name, column.name)

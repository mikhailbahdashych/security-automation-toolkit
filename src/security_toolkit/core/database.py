"""SQLite database management."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Generator

from security_toolkit.core.config import get_settings
from security_toolkit.core.models import (
    ExecutionHistory,
    ExecutionStatus,
    ExecutionType,
    Parameter,
    Script,
    ScriptType,
)

SCHEMA_VERSION = 1

MIGRATIONS = [
    # Version 1: Initial schema
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY
    );

    CREATE TABLE IF NOT EXISTS scripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '',
        path TEXT NOT NULL,
        script_type TEXT NOT NULL CHECK (script_type IN ('python', 'shell')),
        category TEXT DEFAULT 'uncategorized',
        parameters TEXT DEFAULT '[]',
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS execution_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        script_id INTEGER,
        tool_name TEXT,
        execution_type TEXT NOT NULL CHECK (execution_type IN ('script', 'tool')),
        parameters TEXT DEFAULT '{}',
        status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        output_path TEXT,
        error_message TEXT,
        FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS configuration (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT,
        value_type TEXT DEFAULT 'string'
    );

    CREATE INDEX IF NOT EXISTS idx_scripts_name ON scripts(name);
    CREATE INDEX IF NOT EXISTS idx_scripts_category ON scripts(category);
    CREATE INDEX IF NOT EXISTS idx_execution_history_script_id ON execution_history(script_id);
    CREATE INDEX IF NOT EXISTS idx_execution_history_status ON execution_history(status);
    CREATE INDEX IF NOT EXISTS idx_execution_history_started_at ON execution_history(started_at);
    CREATE INDEX IF NOT EXISTS idx_configuration_key ON configuration(key);

    INSERT OR REPLACE INTO schema_version (version) VALUES (1);
    """,
]


class Database:
    """SQLite database manager."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Initialize database connection."""
        self.db_path = db_path or get_settings().db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self.connection() as conn:
            cursor = conn.cursor()

            # Check current schema version
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
            )
            if cursor.fetchone() is None:
                current_version = 0
            else:
                cursor.execute("SELECT MAX(version) FROM schema_version")
                result = cursor.fetchone()
                current_version = result[0] if result and result[0] else 0

            # Apply pending migrations
            for version, migration in enumerate(MIGRATIONS, start=1):
                if version > current_version:
                    cursor.executescript(migration)

            conn.commit()

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # Script CRUD operations

    def create_script(self, script: Script) -> Script:
        """Create a new script."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scripts (name, description, path, script_type, category, parameters, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    script.name,
                    script.description,
                    script.path,
                    script.script_type.value,
                    script.category,
                    json.dumps([p.model_dump() for p in script.parameters]),
                    1 if script.is_active else 0,
                ),
            )
            conn.commit()
            script.id = cursor.lastrowid
            return script

    def get_script(
        self,
        script_id: int | None = None,
        name: str | None = None,
        active_only: bool = True,
    ) -> Script | None:
        """Get a script by ID or name."""
        with self.connection() as conn:
            cursor = conn.cursor()
            active_clause = " AND is_active = 1" if active_only else ""
            if script_id is not None:
                cursor.execute(f"SELECT * FROM scripts WHERE id = ?{active_clause}", (script_id,))
            elif name is not None:
                cursor.execute(f"SELECT * FROM scripts WHERE name = ?{active_clause}", (name,))
            else:
                return None

            row = cursor.fetchone()
            return self._row_to_script(row) if row else None

    def list_scripts(
        self,
        category: str | None = None,
        active_only: bool = True,
    ) -> list[Script]:
        """List all scripts, optionally filtered."""
        with self.connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM scripts WHERE 1=1"
            params: list[Any] = []

            if active_only:
                query += " AND is_active = 1"
            if category:
                query += " AND category = ?"
                params.append(category)

            query += " ORDER BY name"
            cursor.execute(query, params)
            return [self._row_to_script(row) for row in cursor.fetchall()]

    def update_script(self, script: Script) -> Script:
        """Update an existing script."""
        if script.id is None:
            raise ValueError("Script ID is required for update")

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scripts
                SET name = ?, description = ?, path = ?, script_type = ?,
                    category = ?, parameters = ?, is_active = ?
                WHERE id = ?
                """,
                (
                    script.name,
                    script.description,
                    script.path,
                    script.script_type.value,
                    script.category,
                    json.dumps([p.model_dump() for p in script.parameters]),
                    1 if script.is_active else 0,
                    script.id,
                ),
            )
            conn.commit()
            return script

    def delete_script(self, script_id: int) -> bool:
        """Permanently delete a script from the database."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scripts WHERE id = ?", (script_id,))
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_script(self, row: sqlite3.Row) -> Script:
        """Convert database row to Script model."""
        params_data = json.loads(row["parameters"]) if row["parameters"] else []
        parameters = [Parameter(**p) for p in params_data]

        return Script(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            path=row["path"],
            script_type=ScriptType(row["script_type"]),
            category=row["category"] or "uncategorized",
            parameters=parameters,
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
        )

    # Execution history operations

    def create_execution(self, execution: ExecutionHistory) -> ExecutionHistory:
        """Create a new execution history record."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO execution_history
                (script_id, tool_name, execution_type, parameters, status, started_at, output_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution.script_id,
                    execution.tool_name,
                    execution.execution_type.value,
                    json.dumps(execution.parameters),
                    execution.status.value,
                    execution.started_at,
                    execution.output_path,
                ),
            )
            conn.commit()
            execution.id = cursor.lastrowid
            return execution

    def update_execution(self, execution: ExecutionHistory) -> ExecutionHistory:
        """Update an execution history record."""
        if execution.id is None:
            raise ValueError("Execution ID is required for update")

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE execution_history
                SET status = ?, completed_at = ?, output_path = ?, error_message = ?
                WHERE id = ?
                """,
                (
                    execution.status.value,
                    execution.completed_at,
                    execution.output_path,
                    execution.error_message,
                    execution.id,
                ),
            )
            conn.commit()
            return execution

    def get_execution(self, execution_id: int) -> ExecutionHistory | None:
        """Get an execution record by ID."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM execution_history WHERE id = ?", (execution_id,))
            row = cursor.fetchone()
            return self._row_to_execution(row) if row else None

    def list_executions(
        self,
        script_id: int | None = None,
        tool_name: str | None = None,
        status: ExecutionStatus | None = None,
        limit: int = 50,
    ) -> list[ExecutionHistory]:
        """List execution history records."""
        with self.connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM execution_history WHERE 1=1"
            params: list[Any] = []

            if script_id is not None:
                query += " AND script_id = ?"
                params.append(script_id)
            if tool_name is not None:
                query += " AND tool_name = ?"
                params.append(tool_name)
            if status is not None:
                query += " AND status = ?"
                params.append(status.value)

            query += " ORDER BY started_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [self._row_to_execution(row) for row in cursor.fetchall()]

    def _row_to_execution(self, row: sqlite3.Row) -> ExecutionHistory:
        """Convert database row to ExecutionHistory model."""
        return ExecutionHistory(
            id=row["id"],
            script_id=row["script_id"],
            tool_name=row["tool_name"],
            execution_type=ExecutionType(row["execution_type"]),
            parameters=json.loads(row["parameters"]) if row["parameters"] else {},
            status=ExecutionStatus(row["status"]),
            started_at=row["started_at"] or datetime.now(),
            completed_at=row["completed_at"],
            output_path=row["output_path"],
            error_message=row["error_message"],
        )

    # Configuration operations

    def get_config(self, key: str) -> Any:
        """Get a configuration value."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value, value_type FROM configuration WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row is None:
                return None

            value, value_type = row["value"], row["value_type"]
            if value_type == "int":
                return int(value) if value else None
            elif value_type == "bool":
                return value.lower() in ("true", "1", "yes") if value else False
            elif value_type == "json":
                return json.loads(value) if value else None
            return value

    def set_config(self, key: str, value: Any, value_type: str = "string") -> None:
        """Set a configuration value."""
        with self.connection() as conn:
            cursor = conn.cursor()
            str_value = json.dumps(value) if value_type == "json" else str(value)
            cursor.execute(
                """
                INSERT INTO configuration (key, value, value_type)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = ?, value_type = ?
                """,
                (key, str_value, value_type, str_value, value_type),
            )
            conn.commit()

    # Statistics

    def get_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        with self.connection() as conn:
            cursor = conn.cursor()

            stats: dict[str, Any] = {}

            # Script counts
            cursor.execute("SELECT COUNT(*) FROM scripts WHERE is_active = 1")
            stats["active_scripts"] = cursor.fetchone()[0]

            cursor.execute("SELECT category, COUNT(*) FROM scripts WHERE is_active = 1 GROUP BY category")
            stats["scripts_by_category"] = dict(cursor.fetchall())

            # Execution counts
            cursor.execute("SELECT COUNT(*) FROM execution_history")
            stats["total_executions"] = cursor.fetchone()[0]

            cursor.execute("SELECT status, COUNT(*) FROM execution_history GROUP BY status")
            stats["executions_by_status"] = dict(cursor.fetchall())

            cursor.execute(
                """
                SELECT execution_type, COUNT(*)
                FROM execution_history
                GROUP BY execution_type
                """
            )
            stats["executions_by_type"] = dict(cursor.fetchall())

            # Recent activity
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM execution_history
                WHERE started_at > datetime('now', '-24 hours')
                """
            )
            stats["executions_last_24h"] = cursor.fetchone()[0]

            return stats


@lru_cache
def get_database() -> Database:
    """Get cached database instance."""
    return Database()

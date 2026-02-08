"""Tests for database module."""

import pytest

from security_toolkit.core.database import Database
from security_toolkit.core.models import (
    ExecutionHistory,
    ExecutionStatus,
    ExecutionType,
    Parameter,
    ParameterType,
    Script,
    ScriptType,
)


class TestDatabase:
    """Tests for Database class."""

    def test_database_initialization(self, temp_db):
        """Test database is properly initialized."""
        assert temp_db.db_path.exists()

    def test_create_script(self, temp_db):
        """Test creating a script."""
        script = Script(
            name="test-script",
            description="A test script",
            path="/path/to/script.py",
            script_type=ScriptType.PYTHON,
            category="testing",
            parameters=[
                Parameter(name="input", param_type=ParameterType.FILE, required=True),
            ],
        )

        created = temp_db.create_script(script)

        assert created.id is not None
        assert created.name == "test-script"

    def test_get_script_by_name(self, temp_db):
        """Test retrieving script by name."""
        script = Script(
            name="find-me",
            path="/path/to/script.py",
            script_type=ScriptType.PYTHON,
        )
        temp_db.create_script(script)

        found = temp_db.get_script(name="find-me")

        assert found is not None
        assert found.name == "find-me"

    def test_get_script_by_id(self, temp_db):
        """Test retrieving script by ID."""
        script = Script(
            name="by-id",
            path="/path/to/script.py",
            script_type=ScriptType.SHELL,
        )
        created = temp_db.create_script(script)

        found = temp_db.get_script(script_id=created.id)

        assert found is not None
        assert found.id == created.id

    def test_list_scripts(self, temp_db):
        """Test listing scripts."""
        for i in range(3):
            temp_db.create_script(
                Script(
                    name=f"script-{i}",
                    path=f"/path/to/script{i}.py",
                    script_type=ScriptType.PYTHON,
                )
            )

        scripts = temp_db.list_scripts()

        assert len(scripts) == 3

    def test_list_scripts_by_category(self, temp_db):
        """Test listing scripts filtered by category."""
        temp_db.create_script(
            Script(name="s1", path="/p1.py", script_type=ScriptType.PYTHON, category="cat1")
        )
        temp_db.create_script(
            Script(name="s2", path="/p2.py", script_type=ScriptType.PYTHON, category="cat2")
        )

        scripts = temp_db.list_scripts(category="cat1")

        assert len(scripts) == 1
        assert scripts[0].category == "cat1"

    def test_update_script(self, temp_db):
        """Test updating a script."""
        script = temp_db.create_script(
            Script(
                name="update-me",
                path="/path.py",
                script_type=ScriptType.PYTHON,
                description="Original",
            )
        )

        script.description = "Updated"
        updated = temp_db.update_script(script)

        assert updated.description == "Updated"

    def test_delete_script(self, temp_db):
        """Test soft-deleting a script."""
        script = temp_db.create_script(
            Script(name="delete-me", path="/p.py", script_type=ScriptType.PYTHON)
        )

        result = temp_db.delete_script(script.id)

        assert result is True
        scripts = temp_db.list_scripts(active_only=True)
        assert len(scripts) == 0

    def test_create_execution(self, temp_db):
        """Test creating an execution record."""
        execution = ExecutionHistory(
            tool_name="test-tool",
            execution_type=ExecutionType.TOOL,
            parameters={"key": "value"},
            status=ExecutionStatus.RUNNING,
        )

        created = temp_db.create_execution(execution)

        assert created.id is not None
        assert created.tool_name == "test-tool"

    def test_update_execution(self, temp_db):
        """Test updating an execution record."""
        from datetime import datetime

        execution = temp_db.create_execution(
            ExecutionHistory(
                tool_name="update-exec",
                execution_type=ExecutionType.TOOL,
                status=ExecutionStatus.RUNNING,
            )
        )

        execution.status = ExecutionStatus.SUCCESS
        execution.completed_at = datetime.now()
        updated = temp_db.update_execution(execution)

        assert updated.status == ExecutionStatus.SUCCESS

    def test_list_executions(self, temp_db):
        """Test listing executions."""
        for i in range(5):
            temp_db.create_execution(
                ExecutionHistory(
                    tool_name=f"tool-{i}",
                    execution_type=ExecutionType.TOOL,
                    status=ExecutionStatus.SUCCESS,
                )
            )

        executions = temp_db.list_executions(limit=3)

        assert len(executions) == 3

    def test_get_stats(self, temp_db):
        """Test getting statistics."""
        temp_db.create_script(
            Script(name="s1", path="/p.py", script_type=ScriptType.PYTHON)
        )
        temp_db.create_execution(
            ExecutionHistory(
                tool_name="tool",
                execution_type=ExecutionType.TOOL,
                status=ExecutionStatus.SUCCESS,
            )
        )

        stats = temp_db.get_stats()

        assert stats["active_scripts"] == 1
        assert stats["total_executions"] == 1

    def test_config_get_set(self, temp_db):
        """Test configuration get/set."""
        temp_db.set_config("test_key", "test_value")

        value = temp_db.get_config("test_key")

        assert value == "test_value"

    def test_config_types(self, temp_db):
        """Test configuration with different types."""
        temp_db.set_config("int_val", 42, "int")
        temp_db.set_config("bool_val", True, "bool")
        temp_db.set_config("json_val", {"key": "value"}, "json")

        assert temp_db.get_config("int_val") == 42
        assert temp_db.get_config("bool_val") is True
        assert temp_db.get_config("json_val") == {"key": "value"}

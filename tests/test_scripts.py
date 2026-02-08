"""Tests for script management."""

import pytest

from security_toolkit.core.models import ParameterType
from security_toolkit.scripts.executor import ScriptExecutor
from security_toolkit.scripts.manager import ScriptManager


class TestScriptManager:
    """Tests for ScriptManager."""

    def test_register_script(self, temp_db, sample_script, monkeypatch):
        """Test registering a script."""
        from security_toolkit.scripts import manager as mgr_module
        from security_toolkit.core import config as cfg_module

        # Mock get_database to return temp_db
        monkeypatch.setattr(mgr_module, "get_database", lambda: temp_db)

        manager = ScriptManager()
        manager.db = temp_db

        script = manager.register(
            name="test-script",
            path=str(sample_script),
            description="A test script",
            category="testing",
        )

        assert script.id is not None
        assert script.name == "test-script"

    def test_register_with_parameters(self, temp_db, sample_script):
        """Test registering script with parameters."""
        manager = ScriptManager()
        manager.db = temp_db

        script = manager.register(
            name="param-script",
            path=str(sample_script),
            parameters=[
                {"name": "name", "type": "string", "required": True},
                {"name": "count", "type": "int", "default": 1},
            ],
        )

        assert len(script.parameters) == 2
        assert script.parameters[0].name == "name"
        assert script.parameters[0].required is True

    def test_get_script(self, temp_db, sample_script):
        """Test getting a script by name."""
        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="get-me", path=str(sample_script))
        found = manager.get(name="get-me")

        assert found is not None
        assert found.name == "get-me"

    def test_list_scripts(self, temp_db, sample_script):
        """Test listing scripts."""
        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="script1", path=str(sample_script), category="cat1")
        manager.register(name="script2", path=str(sample_script), category="cat2")

        all_scripts = manager.list()
        assert len(all_scripts) == 2

        cat1_scripts = manager.list(category="cat1")
        assert len(cat1_scripts) == 1

    def test_update_script(self, temp_db, sample_script):
        """Test updating a script."""
        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="update-me", path=str(sample_script), description="Original")
        updated = manager.update(name="update-me", description="Updated")

        assert updated.description == "Updated"

    def test_delete_script(self, temp_db, sample_script):
        """Test deleting a script."""
        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="delete-me", path=str(sample_script))
        result = manager.delete(name="delete-me")

        assert result is True
        assert len(manager.list()) == 0

    def test_validate_parameters_required(self, temp_db, sample_script):
        """Test parameter validation for required params."""
        manager = ScriptManager()
        manager.db = temp_db

        script = manager.register(
            name="validate-test",
            path=str(sample_script),
            parameters=[{"name": "required_param", "type": "string", "required": True}],
        )

        valid, errors = manager.validate_parameters(script, {})
        assert valid is False
        assert len(errors) > 0

    def test_validate_parameters_type_check(self, temp_db, sample_script):
        """Test parameter validation for type checking."""
        manager = ScriptManager()
        manager.db = temp_db

        script = manager.register(
            name="type-test",
            path=str(sample_script),
            parameters=[{"name": "count", "type": "int"}],
        )

        valid, errors = manager.validate_parameters(script, {"count": "not-an-int"})
        assert valid is False

    def test_get_categories(self, temp_db, sample_script):
        """Test getting all categories."""
        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="s1", path=str(sample_script), category="alpha")
        manager.register(name="s2", path=str(sample_script), category="beta")

        categories = manager.get_categories()
        assert "alpha" in categories
        assert "beta" in categories


class TestScriptExecutor:
    """Tests for ScriptExecutor."""

    def test_run_script(self, temp_db, sample_script):
        """Test running a script."""
        from security_toolkit.scripts.manager import ScriptManager

        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="runnable", path=str(sample_script))

        executor = ScriptExecutor()
        executor.db = temp_db
        executor.manager = manager

        execution, stdout, stderr = executor.run(
            script_name="runnable",
            parameters={"name": "Test"},
        )

        assert execution.status.value == "success"
        assert "Hello, Test!" in stdout

    def test_run_script_with_count(self, temp_db, sample_script):
        """Test running script with count parameter."""
        from security_toolkit.scripts.manager import ScriptManager

        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="counter", path=str(sample_script))

        executor = ScriptExecutor()
        executor.db = temp_db
        executor.manager = manager

        execution, stdout, _ = executor.run(
            script_name="counter",
            parameters={"name": "World", "count": 3},
        )

        assert execution.status.value == "success"
        assert stdout.count("Hello, World!") == 3

    def test_run_nonexistent_script(self, temp_db):
        """Test running a script that doesn't exist."""
        from security_toolkit.scripts.manager import ScriptManager

        manager = ScriptManager()
        manager.db = temp_db

        executor = ScriptExecutor()
        executor.db = temp_db
        executor.manager = manager

        with pytest.raises(ValueError, match="not found"):
            executor.run(script_name="nonexistent")

    def test_get_history(self, temp_db, sample_script):
        """Test getting execution history."""
        from security_toolkit.scripts.manager import ScriptManager

        manager = ScriptManager()
        manager.db = temp_db

        manager.register(name="history-test", path=str(sample_script))

        executor = ScriptExecutor()
        executor.db = temp_db
        executor.manager = manager

        executor.run(script_name="history-test")
        executor.run(script_name="history-test")

        history = executor.get_history(script_name="history-test")
        assert len(history) == 2

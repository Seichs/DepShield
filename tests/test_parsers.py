"""Tests for dependency parsers."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from dep_shield.core.parsers import DependencyParser
from dep_shield.core.parsers.base import Dependency, ParsedDependencies
from dep_shield.core.parsers.python import PythonRequirementsParser, PythonPyProjectParser
from dep_shield.core.parsers.nodejs import NodeJSPackageParser, NodeJSYarnParser


@pytest.fixture
def temp_requirements_file(tmp_path):
    """Create a temporary requirements.txt file."""
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text(
        "requests>=2.25.0\n"
        "django==3.2.0\n"
        "flask~=2.0.0\n"
        "# This is a comment\n"
        "urllib3<2.0.0\n"
    )
    return requirements_file


@pytest.fixture
def temp_package_json(tmp_path):
    """Create a temporary package.json file."""
    package_file = tmp_path / "package.json"
    package_file.write_text('''{
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.17.19",
            "express": "~4.17.1"
        },
        "devDependencies": {
            "jest": "^27.0.0"
        }
    }''')
    return package_file


class TestPythonRequirementsParser:
    """Test Python requirements.txt parser."""
    
    def test_can_parse_requirements_file(self, temp_requirements_file):
        """Test that parser can identify requirements files."""
        parser = PythonRequirementsParser()
        assert parser.can_parse(temp_requirements_file)
    
    def test_cannot_parse_other_files(self, tmp_path):
        """Test that parser rejects non-requirements files."""
        parser = PythonRequirementsParser()
        other_file = tmp_path / "other.txt"
        other_file.write_text("some content")
        assert not parser.can_parse(other_file)
    
    def test_parse_requirements_file(self, temp_requirements_file):
        """Test parsing requirements.txt file."""
        parser = PythonRequirementsParser()
        result = parser.parse(temp_requirements_file)
        
        assert isinstance(result, ParsedDependencies)
        assert len(result.dependencies) == 4
        assert result.ecosystem == "python"
        assert result.parser_type == "requirements"
        
        # Check specific dependencies
        deps = {dep.name: dep for dep in result.dependencies}
        assert "requests" in deps
        assert "django" in deps
        assert "flask" in deps
        assert "urllib3" in deps
        
        # Check versions
        assert deps["django"].version == "3.2.0"
        assert deps["requests"].version_specifier == ">=2.25.0"
    
    def test_parse_with_comments_and_empty_lines(self, tmp_path):
        """Test parsing with comments and empty lines."""
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text(
            "# This is a comment\n"
            "\n"
            "requests>=2.25.0\n"
            "# Another comment\n"
            "django==3.2.0\n"
        )
        
        parser = PythonRequirementsParser()
        result = parser.parse(requirements_file)
        
        assert len(result.dependencies) == 2
        assert result.dependencies[0].name == "requests"
        assert result.dependencies[1].name == "django"
    
    def test_parse_editable_requirements(self, tmp_path):
        """Test parsing editable requirements."""
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text(
            "-e git+https://github.com/user/repo.git#egg=my-package\n"
            "-e ./local/path#egg=local-package\n"
        )
        
        parser = PythonRequirementsParser()
        result = parser.parse(requirements_file)
        
        assert len(result.dependencies) == 2
        assert result.dependencies[0].name == "my-package"
        assert result.dependencies[1].name == "local-package"
        assert result.dependencies[0].metadata.get("editable") is True
    
    def test_parse_url_requirements(self, tmp_path):
        """Test parsing URL requirements."""
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text(
            "requests @ https://github.com/psf/requests/archive/v2.25.0.tar.gz\n"
            "django @ git+https://github.com/django/django.git@stable/3.2.x\n"
        )
        
        parser = PythonRequirementsParser()
        result = parser.parse(requirements_file)
        
        assert len(result.dependencies) == 2
        assert result.dependencies[0].name == "requests"
        assert result.dependencies[1].name == "django"
        assert result.dependencies[0].metadata.get("url") is True


class TestPythonPyProjectParser:
    """Test Python pyproject.toml parser."""
    
    def test_can_parse_pyproject_file(self, tmp_path):
        """Test that parser can identify pyproject.toml files."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text("[project]")
        
        parser = PythonPyProjectParser()
        assert parser.can_parse(pyproject_file)
    
    def test_parse_pyproject_toml(self, tmp_path):
        """Test parsing pyproject.toml file."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text('''[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "requests>=2.25.0",
    "django==3.2.0",
    "flask[dev]>=2.0.0"
]

[project.optional-dependencies]
test = [
    "pytest>=6.0",
    "pytest-cov>=2.0"
]
''')
        
        parser = PythonPyProjectParser()
        result = parser.parse(pyproject_file)
        
        assert isinstance(result, ParsedDependencies)
        assert len(result.dependencies) == 5
        assert result.ecosystem == "python"
        assert result.parser_type == "pyproject"
        
        # Check dependencies
        deps = {dep.name: dep for dep in result.dependencies}
        assert "requests" in deps
        assert "django" in deps
        assert "flask" in deps
        assert "pytest" in deps
        assert "pytest-cov" in deps
        
        # Check metadata
        flask_dep = deps["flask"]
        assert flask_dep.metadata.get("extras") == "dev"
        pytest_dep = deps["pytest"]
        assert pytest_dep.metadata.get("group") == "test"


class TestNodeJSPackageParser:
    """Test Node.js package.json parser."""
    
    def test_can_parse_package_json(self, temp_package_json):
        """Test that parser can identify package.json files."""
        parser = NodeJSPackageParser()
        assert parser.can_parse(temp_package_json)
    
    def test_parse_package_json(self, temp_package_json):
        """Test parsing package.json file."""
        parser = NodeJSPackageParser()
        result = parser.parse(temp_package_json)
        
        assert isinstance(result, ParsedDependencies)
        assert len(result.dependencies) == 3
        assert result.ecosystem == "nodejs"
        assert result.parser_type == "package"
        
        # Check dependencies
        deps = {dep.name: dep for dep in result.dependencies}
        assert "lodash" in deps
        assert "express" in deps
        assert "jest" in deps
        
        # Check metadata
        lodash_dep = deps["lodash"]
        assert lodash_dep.metadata.get("type") == "runtime"
        jest_dep = deps["jest"]
        assert jest_dep.metadata.get("type") == "dev"
    
    def test_parse_complex_package_json(self, tmp_path):
        """Test parsing complex package.json with all dependency types."""
        package_file = tmp_path / "package.json"
        package_file.write_text('''{
            "name": "complex-project",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.19"
            },
            "devDependencies": {
                "jest": "^27.0.0"
            },
            "peerDependencies": {
                "react": "^17.0.0"
            },
            "optionalDependencies": {
                "debug": "^4.3.0"
            }
        }''')
        
        parser = NodeJSPackageParser()
        result = parser.parse(package_file)
        
        assert len(result.dependencies) == 4
        
        deps = {dep.name: dep for dep in result.dependencies}
        assert deps["lodash"].metadata.get("type") == "runtime"
        assert deps["jest"].metadata.get("type") == "dev"
        assert deps["react"].metadata.get("type") == "peer"
        assert deps["debug"].metadata.get("type") == "optional"


class TestNodeJSYarnParser:
    """Test Node.js yarn.lock parser."""
    
    def test_can_parse_yarn_lock(self, tmp_path):
        """Test that parser can identify yarn.lock files."""
        yarn_file = tmp_path / "yarn.lock"
        yarn_file.write_text("some content")
        
        parser = NodeJSYarnParser()
        assert parser.can_parse(yarn_file)
    
    def test_parse_yarn_lock(self, tmp_path):
        """Test parsing yarn.lock file."""
        yarn_file = tmp_path / "yarn.lock"
        yarn_file.write_text('''lodash@^4.17.19:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-...

express@~4.17.1:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"
  integrity sha512-...
''')
        
        parser = NodeJSYarnParser()
        result = parser.parse(yarn_file)
        
        assert isinstance(result, ParsedDependencies)
        assert len(result.dependencies) == 2
        assert result.ecosystem == "nodejs"
        assert result.parser_type == "yarn"
        
        # Check dependencies
        deps = {dep.name: dep for dep in result.dependencies}
        assert "lodash" in deps
        assert "express" in deps
        
        # Check resolved versions
        assert deps["lodash"].version == "4.17.21"
        assert deps["express"].version == "4.17.1"
        assert deps["lodash"].metadata.get("resolved") is True


class TestParserRegistry:
    """Test the parser registry system."""
    
    def test_register_and_get_parser(self):
        """Test registering and retrieving parsers."""
        registry = DependencyParser
        
        # Test getting existing parsers
        python_req = registry.get_parser("python", "requirements")
        assert python_req is not None
        assert isinstance(python_req, PythonRequirementsParser)
        
        nodejs_pkg = registry.get_parser("nodejs", "package")
        assert nodejs_pkg is not None
        assert isinstance(nodejs_pkg, NodeJSPackageParser)
    
    def test_find_parser_for_file(self, temp_requirements_file, temp_package_json):
        """Test finding appropriate parser for files."""
        registry = DependencyParser
        
        # Test requirements file
        parser = registry.find_parser_for_file(temp_requirements_file)
        assert parser is not None
        assert isinstance(parser, PythonRequirementsParser)
        
        # Test package.json file
        parser = registry.find_parser_for_file(temp_package_json)
        assert parser is not None
        assert isinstance(parser, NodeJSPackageParser)
    
    def test_get_supported_ecosystems(self):
        """Test getting list of supported ecosystems."""
        registry = DependencyParser
        ecosystems = registry.get_supported_ecosystems()
        
        assert "python" in ecosystems
        assert "nodejs" in ecosystems
    
    def test_get_supported_parser_types(self):
        """Test getting list of supported parser types."""
        registry = DependencyParser
        parser_types = registry.get_supported_parser_types()
        
        assert "requirements" in parser_types
        assert "package" in parser_types
        assert "pyproject" in parser_types
        assert "yarn" in parser_types


class TestDependencyModel:
    """Test the Dependency data model."""
    
    def test_dependency_creation(self):
        """Test creating a dependency."""
        dep = Dependency(
            name="requests",
            version="2.25.0",
            ecosystem="python",
            source_file=Path("requirements.txt"),
            line_number=1
        )
        
        assert dep.name == "requests"
        assert dep.version == "2.25.0"
        assert dep.ecosystem == "python"
        assert dep.source_file == Path("requirements.txt")
        assert dep.line_number == 1
    
    def test_dependency_normalization(self):
        """Test dependency name normalization."""
        dep = Dependency(name="  REQUESTS  ", ecosystem="python")
        assert dep.name == "requests"
    
    def test_dependency_validation(self):
        """Test dependency validation."""
        with pytest.raises(ValueError, match="Dependency name cannot be empty"):
            Dependency(name="", ecosystem="python")
    
    def test_dependency_version_extraction(self):
        """Test version extraction from specifiers."""
        dep = Dependency(
            name="requests",
            version_specifier=">=2.25.0,<3.0.0",
            ecosystem="python"
        )
        
        # Should extract version from specifier
        assert dep.version == "2.25.0"
    
    def test_dependency_vulnerability_check(self):
        """Test vulnerability checking."""
        dep = Dependency(name="requests", version="2.25.0", ecosystem="python")
        
        # Test vulnerable version
        assert dep.is_vulnerable(["2.25.0"])
        
        # Test non-vulnerable version
        assert not dep.is_vulnerable(["2.26.0"])
        
        # Test without version
        dep_no_version = Dependency(name="requests", ecosystem="python")
        assert not dep_no_version.is_vulnerable(["2.25.0"])
    
    def test_dependency_version_range_matching(self):
        """Test version range matching."""
        dep = Dependency(name="requests", version="2.25.0", ecosystem="python")
        
        # Test matching range
        assert dep.matches_version_range(">=2.25.0,<3.0.0")
        
        # Test non-matching range
        assert not dep.matches_version_range(">=3.0.0")
        
        # Test without version
        dep_no_version = Dependency(name="requests", ecosystem="python")
        assert not dep_no_version.matches_version_range(">=2.25.0")
    
    def test_dependency_equality(self):
        """Test dependency equality."""
        dep1 = Dependency(name="requests", ecosystem="python")
        dep2 = Dependency(name="requests", ecosystem="python")
        dep3 = Dependency(name="django", ecosystem="python")
        
        assert dep1 == dep2
        assert dep1 != dep3
    
    def test_dependency_hash(self):
        """Test dependency hashing."""
        dep1 = Dependency(name="requests", ecosystem="python")
        dep2 = Dependency(name="requests", ecosystem="python")
        
        assert hash(dep1) == hash(dep2)
        
        # Test in set
        deps = {dep1, dep2}
        assert len(deps) == 1  # Should deduplicate


class TestParsedDependencies:
    """Test the ParsedDependencies container."""
    
    def test_parsed_dependencies_creation(self):
        """Test creating parsed dependencies."""
        deps = ParsedDependencies(
            source_file=Path("requirements.txt"),
            ecosystem="python",
            parser_type="requirements"
        )
        
        assert deps.source_file == Path("requirements.txt")
        assert deps.ecosystem == "python"
        assert deps.parser_type == "requirements"
        assert len(deps.dependencies) == 0
    
    def test_add_dependency(self):
        """Test adding dependencies."""
        deps = ParsedDependencies()
        
        dep1 = Dependency(name="requests", ecosystem="python")
        dep2 = Dependency(name="django", ecosystem="python")
        
        deps.add_dependency(dep1)
        deps.add_dependency(dep2)
        
        assert len(deps.dependencies) == 2
        assert deps.dependencies[0].name == "requests"
        assert deps.dependencies[1].name == "django"
    
    def test_get_dependency_names(self):
        """Test getting dependency names."""
        deps = ParsedDependencies()
        deps.add_dependency(Dependency(name="requests", ecosystem="python"))
        deps.add_dependency(Dependency(name="django", ecosystem="python"))
        
        names = deps.get_dependency_names()
        assert "requests" in names
        assert "django" in names
        assert len(names) == 2
    
    def test_find_dependency(self):
        """Test finding dependencies by name."""
        deps = ParsedDependencies()
        deps.add_dependency(Dependency(name="requests", ecosystem="python"))
        deps.add_dependency(Dependency(name="django", ecosystem="python"))
        
        found = deps.find_dependency("requests")
        assert found is not None
        assert found.name == "requests"
        
        not_found = deps.find_dependency("nonexistent")
        assert not_found is None
    
    def test_filter_by_ecosystem(self):
        """Test filtering dependencies by ecosystem."""
        deps = ParsedDependencies()
        deps.add_dependency(Dependency(name="requests", ecosystem="python"))
        deps.add_dependency(Dependency(name="lodash", ecosystem="nodejs"))
        deps.add_dependency(Dependency(name="django", ecosystem="python"))
        
        python_deps = deps.filter_by_ecosystem("python")
        assert len(python_deps) == 2
        assert all(dep.ecosystem == "python" for dep in python_deps)
        
        nodejs_deps = deps.filter_by_ecosystem("nodejs")
        assert len(nodejs_deps) == 1
        assert nodejs_deps[0].name == "lodash" 
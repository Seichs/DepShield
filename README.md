# DepShield

A professional, scalable Python CLI tool for scanning project dependencies against known vulnerabilities using the [OSV.dev](https://osv.dev) vulnerability database.

## Features

- **Multi-ecosystem Support**: Python, Node.js, Ruby, Java, Go, Rust, PHP, .NET, and more
- **Dual Mode Operation**: 
  - `online` → queries the OSV.dev public API
  - `offline` → scans a local clone of the OSV GitHub vulnerability database
- **High Performance**: Async I/O, memory optimization, and performance monitoring
- **Rich Output**: Beautiful console output with detailed vulnerability information
- **JSON Export**: Machine-readable output for CI/CD integration
- **Advanced Features**: Plugin system, performance benchmarking, and comprehensive logging

## Installation

### From PyPI

```bash
python3 -m pip install dep-shield
```

### From Source

```bash
git clone https://github.com/depshield/depshield.git
cd depshield
python3 -m pip install -e .
```

## Quick Start

### Online Mode (Default)

Scan a project using the OSV.dev API:

```bash
depshield scan /path/to/project
```

### Offline Mode

Scan using a local OSV database:

```bash
depshield scan /path/to/project --mode offline --database /path/to/osv-database
```

**Important**: For offline mode, you need to clone the correct vulnerability database. The OSV service repository doesn't contain the actual vulnerability data.

### Save Results to JSON

```bash
depshield scan /path/to/project --output results.json
```

## Usage

### Basic Scanning

```bash
# Scan current directory
depshield scan

# Scan specific directory
depshield scan /path/to/project

# Verbose output
depshield scan --verbose

# Show performance metrics
depshield scan --performance
```

### Output Options

```bash
# Save results to JSON file
depshield scan --output results.json

# Hide detailed vulnerability information
depshield scan --no-details

# Show performance summary
depshield scan --performance
```

### Advanced Options

```bash
# Use offline mode with local database
depshield scan --mode offline --database ~/advisory-database

# Add custom ignore patterns
depshield scan --ignore "**/vendor/**" --ignore "**/node_modules/**"

# Test connectivity
depshield test --mode online

# Test offline database
depshield test --mode offline --database ~/advisory-database

# Show tool information
depshield info
```

## Supported Ecosystems

DepShield supports parsing dependencies from the following ecosystems:

### Python
- `requirements.txt`
- `pyproject.toml`
- `setup.py`
- `Pipfile`
- `poetry.lock`

### Node.js
- `package.json`
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`

### Ruby
- `Gemfile`
- `Gemfile.lock`

### Java
- `pom.xml`
- `build.gradle`
- `build.gradle.kts`

### Go
- `go.mod`
- `go.sum`

### Rust
- `Cargo.toml`
- `Cargo.lock`

### PHP
- `composer.json`
- `composer.lock`

### .NET
- `*.csproj`
- `*.vbproj`
- `packages.config`

### Docker
- `Dockerfile`
- `docker-compose.yml`

## Examples

### Example 1: Basic Python Project Scan

```bash
# Project structure
my-project/
├── requirements.txt
├── pyproject.toml
└── src/

# Scan for vulnerabilities
depshield scan my-project
```

Output:
```
Scanning for dependency files in my-project...
Found 2 dependency files
Parsing dependencies...
  ✓ requirements.txt (15 dependencies)
  ✓ pyproject.toml (8 dependencies)
Total dependencies: 23
Querying OSV API...

┌─────────────────────────────────────────────────────────────────────────────┐
│ Found 3 vulnerabilities!                                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Scan Summary:                                                             │
│ • Dependencies scanned: 23                                                │
│ • Vulnerable dependencies: 2                                              │
│ • Total vulnerabilities: 3                                                │
│ • Scan time: 2.34s                                                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Vulnerabilities Found                                                     │
├─────────────┬─────────┬──────────────────────┬──────────┬─────────────────┤
│ Package     │ Version │ Vulnerability ID     │ Severity │ Summary         │
├─────────────┼─────────┼──────────────────────┼──────────┼─────────────────┤
│ requests    │ 2.25.0  │ GHSA-8v4j-7jgf-5qgx │ HIGH     │ SSRF in...      │
│ urllib3     │ 1.26.0  │ GHSA-6pwq-5xcr-9w8j │ MEDIUM   │ CRLF injection  │
│ django      │ 3.2.0   │ GHSA-2qrx-6q5v-x82x │ CRITICAL │ SQL injection   │
└─────────────┴─────────┴──────────────────────┴──────────┴─────────────────┘
```

### Example 2: Node.js Project with JSON Output

```bash
depshield scan my-nodejs-project --output vulnerabilities.json --no-details
```

Generated `vulnerabilities.json`:
```json
{
  "scan_summary": {
    "total_dependencies": 45,
    "vulnerable_dependencies": 3,
    "total_vulnerabilities": 5,
    "scan_time_seconds": 1.87,
    "timestamp": "2024-01-15T10:30:45.123456"
  },
  "vulnerabilities": [
    {
      "dependency": {
        "name": "lodash",
        "version": "4.17.19",
        "ecosystem": "nodejs",
        "source_file": "package.json",
        "line_number": null,
        "metadata": {"type": "runtime"}
      },
      "vulnerability": {
        "id": "GHSA-p6mc-m468-83gw",
        "summary": "Prototype pollution in lodash",
        "details": "A prototype pollution vulnerability...",
        "severity": "HIGH",
        "affected_packages": [...],
        "references": [...],
        "published_date": "2021-07-20T00:00:00Z"
      },
      "confidence": 0.95,
      "match_reason": "Version 4.17.19 matches affected range",
      "affected_versions": ["<4.17.21"]
    }
  ]
}
```

### Example 3: Offline Mode with Local Database

```bash
# Clone the GitHub Advisory Database (recommended)
git clone https://github.com/github/advisory-database.git ~/advisory-database

# Alternative: Clone PyPA Advisory Database for Python-specific vulnerabilities
git clone https://github.com/pypa/advisory-database.git ~/pypa-advisory

# Scan using local database
depshield scan my-project --mode offline --database ~/advisory-database
```

**Database Recommendations:**
- **GitHub Advisory Database**: Most comprehensive, covers multiple ecosystems
- **PyPA Advisory Database**: Python-specific vulnerabilities only
- **OSV Database**: Contains the OSV service code, not vulnerability data

## Configuration

### Environment Variables

- `DEPSHIELD_LOG_LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR)
- `DEPSHIELD_LOG_FILE`: Path to log file
- `DEPSHIELD_TIMEOUT`: API timeout in seconds (default: 30)
- `DEPSHIELD_VERBOSE_BENCHMARK`: Enable verbose performance benchmarking

### Offline Database Setup

For optimal offline scanning, follow these steps:

1. **Clone the recommended database:**
   ```bash
   git clone https://github.com/github/advisory-database.git ~/advisory-database
   ```

2. **Keep it updated:**
   ```bash
   cd ~/advisory-database
   git pull origin main
   ```

3. **Verify the setup:**
   ```bash
   depshield test --mode offline --database ~/advisory-database
   ```

**Note**: The GitHub Advisory Database is updated regularly and contains the most comprehensive vulnerability data across multiple ecosystems.

### Ignore Patterns

DepShield automatically ignores common directories and files:

- `node_modules/`
- `.git/`
- `__pycache__/`
- `.venv/`, `venv/`
- `dist/`, `build/`
- And more...

Add custom ignore patterns:

```bash
depshield scan --ignore "**/vendor/**" --ignore "**/custom-ignore/**"
```

## Performance

DepShield is optimized for performance:

- **Async I/O**: Non-blocking API calls for online mode
- **Memory Efficient**: Generators and lazy evaluation
- **Caching**: Intelligent caching of vulnerability data and scan results
- **Indexing**: Fast package lookup in offline mode
- **Benchmarking**: Built-in performance monitoring
- **Deduplication**: Automatic removal of duplicate dependencies

### Performance Monitoring

```bash
depshield scan --performance
```

This shows detailed performance metrics including:
- Execution time per operation
- Memory usage
- API call statistics
- Database query performance

## Development

### Setup Development Environment

```bash
git clone https://github.com/depshield/depshield.git
cd depshield
python3 -m pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
python3 -m pytest

# Run with coverage
python3 -m pytest --cov=dep_shield

# Run specific test
python3 -m pytest tests/test_parsers.py
```

### Code Quality

```bash
# Type checking
python3 -m mypy dep_shield/

# Linting
python3 -m ruff check dep_shield/

# Formatting
python3 -m black dep_shield/
```

### Adding New Parsers

DepShield uses a plugin system for parsers. To add a new parser:

1. Create a new parser class inheriting from `BaseParser`
2. Register it with the `@register_parser` decorator
3. Add tests

Example:
```python
from dep_shield.core.parsers.base import BaseParser
from dep_shield.core.parsers.registry import register_parser

@register_parser("new_ecosystem", "new_format")
class NewEcosystemParser(BaseParser):
    def can_parse(self, file_path):
        # Implementation
        pass
    
    def parse(self, file_path):
        # Implementation
        pass
```

## Architecture

```
dep_shield/
├── cli/                # CLI interface (typer-based)
├── core/               # Parsing and version matching logic
│   ├── parsers/        # Dependency file parsers
│   └── matcher.py      # CVE matcher logic
├── osv/                # Online/offline data clients
│   ├── online.py       # OSV.dev API client
│   └── offline.py      # Local database loader
├── output/             # Output formatters
├── utils/              # Helpers and logging
└── tests/              # pytest unit tests
```

### Key Features

- **Plugin System**: Extensible parser architecture with decorator-based registration
- **Dual Mode**: Online API queries and offline local database scanning
- **Version Matching**: Sophisticated version range parsing and comparison
- **Result Caching**: Persistent storage of scan results for quick access
- **Performance Monitoring**: Built-in benchmarking and memory tracking

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OSV.dev](https://osv.dev) for providing the vulnerability database
- [Rich](https://github.com/Textualize/rich) for beautiful console output
- [Typer](https://github.com/tiangolo/typer) for the CLI framework
- [aiohttp](https://github.com/aio-libs/aiohttp) for async HTTP client

## Troubleshooting

### Common Issues

**SSL Certificate Errors (macOS)**
- DepShield automatically handles SSL certificate issues on macOS
- If you encounter SSL errors, the tool will use appropriate fallback settings

**Offline Mode Not Working**
- Ensure you've cloned the correct database (GitHub Advisory Database, not OSV service)
- Verify the database path exists and contains vulnerability JSON files
- Run `depshield test --mode offline --database /path/to/database` to verify

**No Vulnerabilities Found**
- Check that your dependencies have version information
- Verify the ecosystem mapping (e.g., "python" → "PyPI")
- Use `--verbose` flag for detailed debugging information

**Performance Issues**
- Use `--performance` flag to monitor execution time
- Consider using offline mode for large projects
- Enable verbose benchmarking with `DEPSHIELD_VERBOSE_BENCHMARK=1`


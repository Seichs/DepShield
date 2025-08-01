"""Main CLI interface for DepShield."""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from ..utils.logging import setup_logging, get_logger
from ..utils.path_utils import find_dependency_files
from ..core.parsers import DependencyParser
from ..core.matcher import VulnerabilityMatcher
from ..osv.online import OSVOnlineClient, OSVQuery
from ..osv.offline import OSVOfflineClient, OSVDatabaseConfig
from ..output.formatters import ConsoleFormatter, JSONFormatter

app = typer.Typer(
    name="depshield",
    help="A professional CLI tool for scanning project dependencies against known vulnerabilities",
    add_completion=False
)

console = Console()
logger = get_logger("CLI")

# File to store last scan results
RESULTS_CACHE_FILE = Path.home() / ".depshield_results.json"


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the project directory to scan"
    ),
    mode: str = typer.Option(
        "online",
        "--mode",
        "-m",
        help="Scan mode: 'online' (OSV API) or 'offline' (local database)"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for JSON results"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging"
    ),
    performance: bool = typer.Option(
        False,
        "--performance",
        help="Show performance summary"
    ),
    database_path: Optional[Path] = typer.Option(
        None,
        "--database",
        help="Path to local OSV database (required for offline mode)"
    ),
    ignore_patterns: Optional[List[str]] = typer.Option(
        None,
        "--ignore",
        help="Additional ignore patterns"
    )
) -> None:
    """Scan a project for vulnerable dependencies."""
    
            # Setup logging
    setup_logging(verbose=verbose)
    
    # Enable debug logging for matcher if verbose
    if verbose:
        import logging
        logging.getLogger("VulnerabilityMatcher").setLevel(logging.DEBUG)
    
    try:
        # Validate inputs
        if not path.exists():
            console.print(f"[red]Error: Path does not exist: {path}[/red]")
            raise typer.Exit(1)
        
        if mode == "offline" and not database_path:
            console.print("[red]Error: Database path is required for offline mode[/red]")
            raise typer.Exit(1)
        
        # Find dependency files
        console.print(f"Scanning for dependency files in {path}...")
        dependency_files = find_dependency_files(path, ignore_patterns)
        
        if not dependency_files:
            console.print("[yellow]No dependency files found[/yellow]")
            return
        
        console.print(f"Found {len(dependency_files)} dependency files")
        
        # Parse dependencies
        console.print("Parsing dependencies...")
        all_dependencies = []
        for dep_file in dependency_files:
            try:
                parsed = DependencyParser.parse_file(dep_file.path)
                if parsed:
                    all_dependencies.extend(parsed.dependencies)
                    console.print(f"  ✓ {dep_file.path.name} ({len(parsed.dependencies)} dependencies)")
            except Exception as e:
                console.print(f"  ✗ {dep_file.path.name}: {e}")
        
        if not all_dependencies:
            console.print("[yellow]No dependencies found[/yellow]")
            return
        
        # Deduplicate dependencies by name and version
        seen_deps = set()
        unique_dependencies = []
        for dep in all_dependencies:
            dep_key = (dep.name.lower(), dep.version)
            if dep_key not in seen_deps:
                seen_deps.add(dep_key)
                unique_dependencies.append(dep)
        
        console.print(f"Total dependencies: {len(all_dependencies)}")
        console.print(f"Unique dependencies: {len(unique_dependencies)}")
        
        # Use unique dependencies for scanning
        all_dependencies = unique_dependencies
        
        # Scan for vulnerabilities
        start_time = time.perf_counter()
        
        if mode == "online":
            matches = asyncio.run(_scan_online(all_dependencies))
        else:
            matches = _scan_offline(all_dependencies, database_path)
        
        scan_time = time.perf_counter() - start_time
        
        # Save results for later display
        _save_scan_results(matches, len(all_dependencies), scan_time)
        
        # Show only summary
        console_formatter = ConsoleFormatter(console)
        console_formatter.format_scan_summary(
            matches=matches,
            total_dependencies=len(all_dependencies),
            scan_time=scan_time
        )
        
        # Save JSON output if requested
        if output:
            json_formatter = JSONFormatter(output)
            results = json_formatter.format_scan_results(
                matches=matches,
                total_dependencies=len(all_dependencies),
                scan_time=scan_time
            )
            json_formatter.save_results(results)
        
        # Show performance summary if requested
        if performance:
            console.print("\n[bold cyan]Performance Summary:[/bold cyan]")
            # This would show performance metrics from the matcher and clients
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


async def _scan_online(dependencies: List) -> List:
    """Scan dependencies using online OSV API.
    
    Args:
        dependencies: List of dependencies to scan
        
    Returns:
        List of vulnerability matches
    """
    # Prepare packages for API queries
    packages = []
    
    # Map our ecosystem names to OSV API ecosystem names
    ecosystem_mapping = {
        "python": "PyPI",
        "nodejs": "npm", 
        "ruby": "RubyGems",
        "java": "Maven",
        "go": "Go",
        "rust": "crates.io",
        "php": "Packagist",
        "dotnet": "NuGet"
    }
    
    for dep in dependencies:
        # Only include packages with valid ecosystems
        if dep.ecosystem and dep.ecosystem.lower() in ecosystem_mapping:
            packages.append({
                "name": dep.name,
                "ecosystem": ecosystem_mapping[dep.ecosystem.lower()]
            })
    
    if not packages:
        console.print("[yellow]No valid packages found for scanning[/yellow]")
        return []
    
    # Query vulnerabilities with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Querying OSV API...", total=len(packages))
        
        async with OSVOnlineClient() as client:
            vulnerabilities = await client.query_vulnerabilities_for_packages(packages)
            progress.update(task, completed=len(packages))
    
    # Match vulnerabilities
    matcher = VulnerabilityMatcher()
    matches = matcher.match_dependencies(dependencies, vulnerabilities)
    
    return matches


def _save_scan_results(matches: List, total_dependencies: int, scan_time: float) -> None:
    """Save scan results to cache file.
    
    Args:
        matches: List of vulnerability matches
        total_dependencies: Total dependencies scanned
        scan_time: Scan time in seconds
    """
    
    # Convert matches to serializable format
    serializable_matches = []
    for match in matches:
        serializable_match = {
            'dependency': {
                'name': match.dependency.name,
                'version': match.dependency.version,
                'ecosystem': match.dependency.ecosystem
            },
            'vulnerability': {
                'id': match.vulnerability.id,
                'summary': match.vulnerability.summary,
                'details': match.vulnerability.details,
                'severity': match.vulnerability.severity,
                'references': match.vulnerability.references
            },
            'confidence': match.confidence,
            'match_reason': match.match_reason,
            'affected_versions': match.affected_versions
        }
        serializable_matches.append(serializable_match)
    
    cache_data = {
        'timestamp': datetime.now().isoformat(),
        'matches': serializable_matches,
        'total_dependencies': total_dependencies,
        'scan_time': scan_time
    }
    
    with open(RESULTS_CACHE_FILE, 'w') as f:
        json.dump(cache_data, f, indent=2)


def _load_scan_results() -> Optional[Dict]:
    """Load scan results from cache file.
    
    Returns:
        Cached results or None if not available
    """
    
    if not RESULTS_CACHE_FILE.exists():
        return None
    
    try:
        with open(RESULTS_CACHE_FILE, 'r') as f:
            cache_data = json.load(f)
        
        # Convert back to VulnerabilityMatch objects
        from ..core.matcher import VulnerabilityMatch, Vulnerability
        from ..core.parsers import Dependency
        
        matches = []
        for match_data in cache_data['matches']:
            dependency = Dependency(
                name=match_data['dependency']['name'],
                version=match_data['dependency']['version'],
                ecosystem=match_data['dependency']['ecosystem']
            )
            
            vulnerability = Vulnerability(
                id=match_data['vulnerability']['id'],
                summary=match_data['vulnerability']['summary'],
                details=match_data['vulnerability']['details'],
                severity=match_data['vulnerability']['severity'],
                affected_packages=[],  # Not needed for display
                references=match_data['vulnerability']['references']
            )
            
            match = VulnerabilityMatch(
                dependency=dependency,
                vulnerability=vulnerability,
                confidence=match_data['confidence'],
                match_reason=match_data['match_reason'],
                affected_versions=match_data['affected_versions']
            )
            matches.append(match)
        
        return {
            'matches': matches,
            'total_dependencies': cache_data['total_dependencies'],
            'scan_time': cache_data['scan_time'],
            'timestamp': cache_data['timestamp']
        }
    except Exception as e:
        logger.error(f"Failed to load cached results: {e}")
        return None


def _generate_detailed_report(matches: List, dependencies: List, output_path: Path) -> None:
    """Generate a detailed vulnerability report file.
    
    Args:
        matches: List of vulnerability matches
        dependencies: List of all dependencies
        output_path: Path to output file
    """
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("DEPENDENCY VULNERABILITY REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Scan Summary:\n")
        f.write(f"• Total dependencies scanned: {len(dependencies)}\n")
        f.write(f"• Vulnerable dependencies: {len(set(match.dependency.name for match in matches))}\n")
        f.write(f"• Total vulnerabilities found: {len(matches)}\n")
        f.write(f"• Report generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        if not matches:
            f.write("No vulnerabilities found.\n")
            return
        
        # Group by package
        package_vulns = {}
        for match in matches:
            pkg_name = match.dependency.name
            if pkg_name not in package_vulns:
                package_vulns[pkg_name] = []
            package_vulns[pkg_name].append(match)
        
        # Write detailed report
        for pkg_name, pkg_matches in package_vulns.items():
            f.write(f"Package: {pkg_name}\n")
            f.write("-" * 40 + "\n")
            
            for i, match in enumerate(pkg_matches, 1):
                f.write(f"\nVulnerability {i}:\n")
                f.write(f"  ID: {match.vulnerability.id}\n")
                f.write(f"  Package: {match.dependency.name} {match.dependency.version or 'unknown'}\n")
                f.write(f"  Severity: {str(match.vulnerability.severity or 'UNKNOWN')}\n")
                f.write(f"  Confidence: {match.confidence:.1%}\n")
                f.write(f"  Match Reason: {match.match_reason}\n")
                f.write(f"  Summary: {match.vulnerability.summary}\n")
                f.write(f"  Details: {match.vulnerability.details}\n")
                
                if match.vulnerability.references:
                    f.write(f"  References:\n")
                    for ref in match.vulnerability.references:
                        f.write(f"    • {ref}\n")
                
                f.write("\n")
            
            f.write("\n" + "=" * 80 + "\n\n")


def _scan_offline(dependencies: List, database_path: Path) -> List:
    """Scan dependencies using offline OSV database.
    
    Args:
        dependencies: List of dependencies to scan
        database_path: Path to OSV database
        
    Returns:
        List of vulnerability matches
    """
    console.print("Loading local OSV database...")
    
    # Initialize offline client
    config = OSVDatabaseConfig(database_path)
    client = OSVOfflineClient(config)
    
    # Load vulnerabilities
    vulnerabilities = client.load_vulnerabilities()
    client.build_package_index(vulnerabilities)
    
    # Match vulnerabilities
    matcher = VulnerabilityMatcher()
    matches = matcher.match_dependencies(dependencies, vulnerabilities)
    
    return matches


@app.command()
def test(
    mode: str = typer.Option(
        "online",
        "--mode",
        "-m",
        help="Test mode: 'online' or 'offline'"
    ),
    database_path: Optional[Path] = typer.Option(
        None,
        "--database",
        help="Path to local OSV database (for offline mode)"
    )
) -> None:
    """Test DepShield configuration and connectivity."""
    
    console.print("Testing DepShield...")
    
    if mode == "online":
        # Test online connectivity
        async def test_online():
            async with OSVOnlineClient() as client:
                return await client.test_connection()
        
        success = asyncio.run(test_online())
        if success:
            console.print("Online mode: Connection successful")
        else:
            console.print("Online mode: Connection failed")
            raise typer.Exit(1)
    
    else:
        # Test offline database
        if not database_path:
            console.print("[red]Error: Database path required for offline test[/red]")
            raise typer.Exit(1)
        
        if not database_path.exists():
            console.print(f"[red]Error: Database path does not exist: {database_path}[/red]")
            raise typer.Exit(1)
        
        try:
            config = OSVDatabaseConfig(database_path)
            client = OSVOfflineClient(config)
            
            # Try to load some vulnerabilities
            vulnerabilities = client.load_vulnerabilities(show_progress=False)
            stats = client.get_database_stats()
            
            console.print(f"Offline mode: Database loaded successfully")
            console.print(f"   {stats.get('unique_vulnerabilities', 0)} vulnerabilities")
            console.print(f"   {stats.get('total_packages', 0)} packages")
        
        except Exception as e:
            console.print(f"Offline mode: {e}")
            raise typer.Exit(1)


@app.command()
def report(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the project directory to scan"
    ),
    output: Path = typer.Option(
        Path("vulnerability_report.txt"),
        "--output",
        "-o",
        help="Output file for detailed vulnerability report"
    ),
    mode: str = typer.Option(
        "online",
        "--mode",
        "-m",
        help="Scan mode: 'online' (OSV API) or 'offline' (local database)"
    ),
    database_path: Optional[Path] = typer.Option(
        None,
        "--database",
        help="Path to local OSV database (required for offline mode)"
    ),
    ignore_patterns: Optional[List[str]] = typer.Option(
        None,
        "--ignore",
        help="Additional ignore patterns"
    )
) -> None:
    """Generate a detailed vulnerability report file."""
    
    # Setup logging
    setup_logging(verbose=False)
    
    try:
        # Validate inputs
        if not path.exists():
            console.print(f"[red]Error: Path does not exist: {path}[/red]")
            raise typer.Exit(1)
        
        if mode == "offline" and not database_path:
            console.print("[red]Error: Database path is required for offline mode[/red]")
            raise typer.Exit(1)
        
        # Find dependency files
        console.print(f"Scanning for dependency files in {path}...")
        dependency_files = find_dependency_files(path, ignore_patterns)
        
        if not dependency_files:
            console.print("[yellow]No dependency files found[/yellow]")
            return
        
        console.print(f"Found {len(dependency_files)} dependency files")
        
        # Parse dependencies
        console.print("Parsing dependencies...")
        parser = DependencyParser()
        dependencies = []
        
        for dep_file in dependency_files:
            try:
                parsed = parser.parse_file(dep_file)
                dependencies.extend(parsed.dependencies)
                console.print(f"  ✓ {dep_file.name} ({len(parsed.dependencies)} dependencies)")
                
                # Show some version examples for debugging
                if parsed.dependencies:
                    examples = parsed.dependencies[:3]  # Show first 3
                    for dep in examples:
                        version_info = f"v{dep.version}" if dep.version else "no version"
                        console.print(f"    • {dep.name}: {version_info}")
                    if len(parsed.dependencies) > 3:
                        console.print(f"    • ... and {len(parsed.dependencies) - 3} more")
            except Exception as e:
                console.print(f"  ✗ {dep_file.name}: {e}")
        
        if not dependencies:
            console.print("[yellow]No dependencies found[/yellow]")
            return
        
        # Count dependencies with versions
        dependencies_with_versions = [d for d in dependencies if d.version]
        console.print(f"Total dependencies: {len(dependencies)}")
        console.print(f"Dependencies with versions: {len(dependencies_with_versions)}")
        
        if len(dependencies_with_versions) < len(dependencies):
            console.print(f"[yellow]Warning: {len(dependencies) - len(dependencies_with_versions)} dependencies without version info[/yellow]")
        

        
        # Scan for vulnerabilities
        if mode == "online":
            matches = asyncio.run(_scan_online(dependencies))
        else:
            if not database_path:
                console.print("[red]Error: Database path is required for offline mode[/red]")
                raise typer.Exit(1)
            matches = _scan_offline(dependencies, database_path)
        
        # Generate detailed report
        _generate_detailed_report(matches, dependencies, output)
        
        console.print(f"[green]Detailed report saved to: {output}[/green]")
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def results() -> None:
    """Show detailed vulnerability results from the last scan."""
    cached_results = _load_scan_results()
    
    if not cached_results:
        console.print("[red]Error: No scan results available. Run 'depshield scan' first.[/red]")
        raise typer.Exit(1)
    
    # Show when the scan was performed
    scan_time = datetime.fromisoformat(cached_results['timestamp'])
    console.print(f"[dim]Last scan performed: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
    
    # Show detailed results
    console_formatter = ConsoleFormatter(console)
    console_formatter.format_scan_results(
        matches=cached_results['matches'],
        total_dependencies=cached_results['total_dependencies'],
        scan_time=cached_results['scan_time']
    )


@app.command()
def debug(
    package: str = typer.Argument(..., help="Package name to debug"),
    version: str = typer.Argument(..., help="Package version to debug"),
    ecosystem: str = typer.Option("python", "--ecosystem", "-e", help="Package ecosystem")
) -> None:
    """Debug version matching for a specific package."""
    from ..core.parsers import Dependency
    from ..core.matcher import VulnerabilityMatcher
    
    # Create dependency
    dependency = Dependency(name=package, version=version, ecosystem=ecosystem)
    
    # Query OSV API for this package
    async def query_package():
        packages = [{"name": package, "ecosystem": "PyPI" if ecosystem == "python" else ecosystem}]
        async with OSVOnlineClient() as client:
            vulnerabilities = await client.query_vulnerabilities_for_packages(packages)
        return vulnerabilities
    
    vulnerabilities = asyncio.run(query_package())
    
    if not vulnerabilities:
        console.print(f"[yellow]No vulnerabilities found for {package}[/yellow]")
        return
    
    console.print(f"[green]Found {len(vulnerabilities)} vulnerabilities for {package}[/green]")
    
    # Test matching
    matcher = VulnerabilityMatcher()
    matches = matcher.match_dependencies([dependency], vulnerabilities)
    
    if matches:
        console.print(f"[red]Found {len(matches)} matches for {package} {version}[/red]")
        for match in matches:
            console.print(f"  • {match.vulnerability.id}: {match.match_reason}")
    else:
        console.print(f"[green]No matches found for {package} {version}[/green]")


@app.command()
def info() -> None:
    """Show DepShield information."""
    
    console.print(Panel.fit(
        "[bold blue]DepShield[/bold blue]\n"
        "A professional CLI tool for scanning project dependencies\n"
        "against known vulnerabilities using OSV.dev",
        title="Information"
    ))
    
    # Show supported ecosystems
    ecosystems = DependencyParser.get_supported_ecosystems()
    console.print(f"\n[bold]Supported Ecosystems:[/bold] {', '.join(ecosystems)}")
    
    # Show supported parsers
    parsers = DependencyParser.get_supported_parser_types()
    console.print(f"[bold]Supported Parsers:[/bold] {', '.join(parsers)}")


def main() -> None:
    """Main entry point for DepShield CLI."""
    app()


if __name__ == "__main__":
    main() 
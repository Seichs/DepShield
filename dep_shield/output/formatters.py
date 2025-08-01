"""Output formatters for DepShield results."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.matcher import VulnerabilityMatch
from ..utils.logging import get_logger


class ConsoleFormatter:
    """Rich console formatter for DepShield output."""
    
    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the console formatter.
        
        Args:
            console: Rich console instance
        """
        self.console = console or Console()
        self.logger = get_logger("ConsoleFormatter")
    
    def format_scan_results(
        self,
        matches: List[VulnerabilityMatch],
        total_dependencies: int,
        scan_time: float
    ) -> None:
        """Format and display scan results.
        
        Args:
            matches: List of vulnerability matches
            total_dependencies: Total number of dependencies scanned
            scan_time: Time taken for scan in seconds
        """
        # Summary panel
        summary = self._create_summary_panel(matches, total_dependencies, scan_time)
        self.console.print(summary)
        
        if not matches:
            self.console.print(Panel("No vulnerabilities found!", style="green"))
            return
        
        # Vulnerabilities table
        vuln_table = self._create_vulnerabilities_table(matches)
        self.console.print(vuln_table)
        
        # Show brief instructions
        self.console.print(
            Panel(
                "Use 'depshield results' to view detailed vulnerability table or 'depshield report' to generate a detailed report file.",
                style="blue"
            )
        )
    
    def _create_summary_panel(
        self,
        matches: List[VulnerabilityMatch],
        total_dependencies: int,
        scan_time: float
    ) -> Panel:
        """Create summary panel.
        
        Args:
            matches: List of vulnerability matches
            total_dependencies: Total dependencies scanned
            scan_time: Scan time in seconds
            
        Returns:
            Rich panel with summary
        """
        vulnerable_deps = len(set(match.dependency.name for match in matches))
        
        if matches:
            style = "red"
            title = f"Found {len(matches)} vulnerabilities!"
        else:
            style = "green"
            title = "No vulnerabilities found"
        
        content = f"""
        Scan Summary:
        • Dependencies scanned: {total_dependencies}
        • Vulnerable dependencies: {vulnerable_deps}
        • Total vulnerabilities: {len(matches)}
        • Scan time: {scan_time:.2f}s
        """
        
        return Panel(content, title=title, style=style)
    
    def format_scan_summary(
        self,
        matches: List[VulnerabilityMatch],
        total_dependencies: int,
        scan_time: float
    ) -> None:
        """Format and display scan summary only.
        
        Args:
            matches: List of vulnerability matches
            total_dependencies: Total number of dependencies scanned
            scan_time: Time taken for scan in seconds
        """
        # Show summary only
        summary = self._create_summary_panel(matches, total_dependencies, scan_time)
        self.console.print(summary)
        
        if not matches:
            self.console.print(Panel("No vulnerabilities found!", style="green"))
            return
        
        # Show brief instructions
        self.console.print(
            Panel(
                "Use 'depshield results' to view detailed vulnerability table or 'depshield report' to generate a detailed report file.",
                style="blue"
            )
        )
    
    def _create_vulnerabilities_table(self, matches: List[VulnerabilityMatch]) -> Table:
        """Create vulnerabilities table.
        
        Args:
            matches: List of vulnerability matches
            
        Returns:
            Rich table with vulnerabilities
        """
        table = Table(title="Vulnerabilities Found")
        
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Version", style="blue")
        table.add_column("Vulnerability ID", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Summary", style="white")
        table.add_column("Confidence", style="green")
        
        for match in matches:
            # Extract severity level from complex severity data
            severity_text = self._extract_severity_level(match.vulnerability.severity)
            severity_style = self._get_severity_style(severity_text)
            
            table.add_row(
                match.dependency.name,
                match.dependency.version or "unknown",
                match.vulnerability.id,
                Text(severity_text, style=severity_style),
                match.vulnerability.summary[:50] + "..." if len(match.vulnerability.summary) > 50 else match.vulnerability.summary,
                f"{match.confidence:.1%}"
            )
        
        return table
    
    def _show_detailed_vulnerabilities(self, matches: List[VulnerabilityMatch]) -> None:
        """Show detailed vulnerability information.
        
        Args:
            matches: List of vulnerability matches
        """
        for i, match in enumerate(matches, 1):
            self.console.print(f"\n[bold cyan]Vulnerability {i}:[/bold cyan]")
            
            # Vulnerability details
            details = f"""
            [bold]ID:[/bold] {match.vulnerability.id}
            [bold]Package:[/bold] {match.dependency.name} {match.dependency.version or 'unknown'}
            [bold]Severity:[/bold] {str(match.vulnerability.severity or "UNKNOWN")}
            [bold]Confidence:[/bold] {match.confidence:.1%}
            [bold]Match Reason:[/bold] {match.match_reason}
            
            [bold]Summary:[/bold]
            {match.vulnerability.summary}
            
            [bold]Details:[/bold]
            {match.vulnerability.details}
            """
            
            if match.vulnerability.references:
                details += "\n[bold]References:[/bold]\n"
                for ref in match.vulnerability.references:
                    details += f"• {ref}\n"
            
            self.console.print(Panel(details, style="red"))
    
    def _get_severity_style(self, severity: str) -> str:
        """Get color style for severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            Color style string
        """
        # Handle case where severity might be None, list, or other types
        if not severity:
            return "white"
        
        # Convert to string if it's not already
        severity_str = str(severity)
        severity_lower = severity_str.lower()
        
        if "critical" in severity_lower:
            return "red bold"
        elif "high" in severity_lower:
            return "red"
        elif "medium" in severity_lower:
            return "yellow"
        elif "low" in severity_lower:
            return "blue"
        else:
            return "white"
    
    def _extract_severity_level(self, severity: Any) -> str:
        """Extract severity level from complex severity data.
        
        Args:
            severity: Severity data (can be string, list, or dict)
            
        Returns:
            Extracted severity level string
        """
        if not severity:
            return "UNKNOWN"
        
        # If it's already a string, return it
        if isinstance(severity, str):
            return severity
        
        # If it's a list, try to extract from first item
        if isinstance(severity, list) and severity:
            first_item = severity[0]
            if isinstance(first_item, dict):
                # Look for CVSS score in the dict
                score = first_item.get('score', '')
                if score and 'CVSS' in score:
                    # Extract severity from CVSS score
                    if 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' in score:
                        return "CRITICAL"
                    elif 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' in score or 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' in score:
                        return "HIGH"
                    elif 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' in score:
                        return "MEDIUM"
                    else:
                        return "LOW"
                return "MEDIUM"  # Default for CVSS without specific pattern
        
        # If it's a dict, try to extract score
        if isinstance(severity, dict):
            score = severity.get('score', '')
            if score and 'CVSS' in score:
                return "MEDIUM"  # Default for CVSS
        
        return "UNKNOWN"
    
    def format_performance_summary(self, summary: Dict[str, Any]) -> None:
        """Format and display performance summary.
        
        Args:
            summary: Performance summary dictionary
        """
        if not summary:
            return
        
        table = Table(title="Performance Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in summary.items():
            if key != "metrics":  # Skip detailed metrics
                if isinstance(value, float):
                    table.add_row(key, f"{value:.4f}")
                else:
                    table.add_row(key, str(value))
        
        self.console.print(table)
    
    def format_error(self, error: str, details: Optional[str] = None) -> None:
        """Format and display error message.
        
        Args:
            error: Error message
            details: Optional error details
        """
        content = f"[bold red]Error:[/bold red] {error}"
        if details:
            content += f"\n\n[dim]{details}[/dim]"
        
        self.console.print(Panel(content, style="red"))
    
    def format_info(self, message: str, title: Optional[str] = None) -> None:
        """Format and display info message.
        
        Args:
            message: Info message
            title: Optional panel title
        """
        self.console.print(Panel(message, title=title, style="blue"))


class JSONFormatter:
    """JSON formatter for DepShield output."""
    
    def __init__(self, output_file: Optional[Path] = None) -> None:
        """Initialize the JSON formatter.
        
        Args:
            output_file: Optional output file path
        """
        self.output_file = output_file
        self.logger = get_logger("JSONFormatter")
    
    def format_scan_results(
        self,
        matches: List[VulnerabilityMatch],
        total_dependencies: int,
        scan_time: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Format scan results as JSON.
        
        Args:
            matches: List of vulnerability matches
            total_dependencies: Total dependencies scanned
            scan_time: Scan time in seconds
            metadata: Optional additional metadata
            
        Returns:
            Formatted JSON data
        """
        # Convert matches to dictionaries
        matches_data = []
        for match in matches:
            match_data = {
                "dependency": {
                    "name": match.dependency.name,
                    "version": match.dependency.version,
                    "ecosystem": match.dependency.ecosystem,
                    "source_file": str(match.dependency.source_file) if match.dependency.source_file else None,
                    "line_number": match.dependency.line_number,
                    "metadata": match.dependency.metadata
                },
                "vulnerability": {
                    "id": match.vulnerability.id,
                    "summary": match.vulnerability.summary,
                    "details": match.vulnerability.details,
                    "severity": match.vulnerability.severity,
                    "affected_packages": match.vulnerability.affected_packages,
                    "references": match.vulnerability.references,
                    "published_date": match.vulnerability.published_date,
                    "modified_date": match.vulnerability.modified_date,
                    "withdrawn_date": match.vulnerability.withdrawn_date
                },
                "confidence": match.confidence,
                "match_reason": match.match_reason,
                "affected_versions": match.affected_versions
            }
            matches_data.append(match_data)
        
        # Build result structure
        result = {
            "scan_summary": {
                "total_dependencies": total_dependencies,
                "vulnerable_dependencies": len(set(match.dependency.name for match in matches)),
                "total_vulnerabilities": len(matches),
                "scan_time_seconds": scan_time,
                "timestamp": datetime.now().isoformat()
            },
            "vulnerabilities": matches_data
        }
        
        if metadata:
            result["metadata"] = metadata
        
        return result
    
    def save_results(
        self,
        results: Dict[str, Any],
        output_file: Optional[Path] = None
    ) -> None:
        """Save results to JSON file.
        
        Args:
            results: Results dictionary
            output_file: Output file path (uses instance default if None)
        """
        file_path = output_file or self.output_file
        if not file_path:
            raise ValueError("No output file specified")
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Results saved to {file_path}")
        except IOError as e:
            self.logger.error(f"Failed to save results to {file_path}: {e}")
            raise
    
    def format_performance_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Format performance summary as JSON.
        
        Args:
            summary: Performance summary dictionary
            
        Returns:
            Formatted JSON performance data
        """
        return {
            "performance_summary": summary,
            "timestamp": datetime.now().isoformat()
        }
    
    def format_error(self, error: str, details: Optional[str] = None) -> Dict[str, Any]:
        """Format error as JSON.
        
        Args:
            error: Error message
            details: Optional error details
            
        Returns:
            Formatted JSON error data
        """
        return {
            "error": {
                "message": error,
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
        } 
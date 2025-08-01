"""Performance monitoring utilities for DepShield."""

import time
import cProfile
import pstats
import functools
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from dataclasses import dataclass, field
from pathlib import Path
import tracemalloc
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    
    function_name: str
    execution_time: float
    memory_usage: Optional[int] = None
    memory_peak: Optional[int] = None
    calls: int = 1
    
    def __post_init__(self) -> None:
        """Convert memory usage to MB for readability."""
        if self.memory_usage is not None:
            self.memory_usage = self.memory_usage / 1024 / 1024
        if self.memory_peak is not None:
            self.memory_peak = self.memory_peak / 1024 / 1024


class PerformanceMonitor:
    """Performance monitoring with memory and timing tracking."""
    
    def __init__(self, enable_memory_tracking: bool = True) -> None:
        self.metrics: List[PerformanceMetrics] = []
        self.enable_memory_tracking = enable_memory_tracking
        self.console = Console()
        
        if enable_memory_tracking:
            tracemalloc.start()
    
    @contextmanager
    def measure(self, name: str) -> Any:
        """Context manager for measuring performance.
        
        Args:
            name: Name of the operation being measured
            
        Yields:
            None
        """
        start_time = time.perf_counter()
        start_memory = None
        peak_memory = None
        
        if self.enable_memory_tracking:
            start_memory = tracemalloc.get_traced_memory()[0]
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            if self.enable_memory_tracking:
                current_memory, peak_memory = tracemalloc.get_traced_memory()
                memory_usage = current_memory - start_memory if start_memory else 0
            else:
                memory_usage = None
                peak_memory = None
            
            metric = PerformanceMetrics(
                function_name=name,
                execution_time=execution_time,
                memory_usage=memory_usage,
                memory_peak=peak_memory,
            )
            self.metrics.append(metric)
    
    def benchmark(self, func: F) -> F:
        """Decorator for benchmarking functions.
        
        Args:
            func: Function to benchmark
            
        Returns:
            Wrapped function with performance tracking
        """
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self.measure(func.__name__):
                return func(*args, **kwargs)
        return wrapper
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary.
        
        Returns:
            Dictionary with performance summary
        """
        if not self.metrics:
            return {}
        
        total_time = sum(m.execution_time for m in self.metrics)
        total_memory = sum(m.memory_usage or 0 for m in self.metrics)
        max_peak = max(m.memory_peak or 0 for m in self.metrics)
        
        return {
            "total_executions": len(self.metrics),
            "total_time": total_time,
            "average_time": total_time / len(self.metrics),
            "total_memory": total_memory,
            "max_peak_memory": max_peak,
            "metrics": self.metrics,
        }
    
    def print_summary(self) -> None:
        """Print performance summary to console."""
        summary = self.get_summary()
        if not summary:
            return
        
        table = Table(title="Performance Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Executions", str(summary["total_executions"]))
        table.add_row("Total Time", f"{summary['total_time']:.4f}s")
        table.add_row("Average Time", f"{summary['average_time']:.4f}s")
        
        if self.enable_memory_tracking:
            table.add_row("Total Memory", f"{summary['total_memory']:.2f} MB")
            table.add_row("Max Peak Memory", f"{summary['max_peak_memory']:.2f} MB")
        
        self.console.print(table)
    
    def save_profile(self, output_file: Path) -> None:
        """Save detailed profile to file.
        
        Args:
            output_file: Path to save profile data
        """
        summary = self.get_summary()
        if not summary:
            return
        
        with open(output_file, 'w') as f:
            f.write("DepShield Performance Profile\n")
            f.write("=" * 40 + "\n\n")
            
            f.write(f"Total Executions: {summary['total_executions']}\n")
            f.write(f"Total Time: {summary['total_time']:.4f}s\n")
            f.write(f"Average Time: {summary['average_time']:.4f}s\n")
            
            if self.enable_memory_tracking:
                f.write(f"Total Memory: {summary['total_memory']:.2f} MB\n")
                f.write(f"Max Peak Memory: {summary['max_peak_memory']:.2f} MB\n")
            
            f.write("\nDetailed Metrics:\n")
            f.write("-" * 20 + "\n")
            
            for metric in summary["metrics"]:
                f.write(f"{metric.function_name}:\n")
                f.write(f"  Time: {metric.execution_time:.4f}s\n")
                if metric.memory_usage is not None:
                    f.write(f"  Memory: {metric.memory_usage:.2f} MB\n")
                if metric.memory_peak is not None:
                    f.write(f"  Peak: {metric.memory_peak:.2f} MB\n")
                f.write("\n")


def benchmark(func: F) -> F:
    """Simple benchmark decorator.
    
    Args:
        func: Function to benchmark
        
    Returns:
        Wrapped function with timing
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        
        # Only print if explicitly requested (e.g., with --verbose flag)
        import os
        if os.environ.get('DEPSHIELD_VERBOSE_BENCHMARK'):
            import logging
            logger = logging.getLogger("Performance")
            logger.info(f"{func.__name__} took {end_time - start_time:.4f} seconds")
        return result
    return wrapper


@contextmanager
def profile_function(func_name: str, output_file: Optional[Path] = None) -> Any:
    """Profile a function using cProfile.
    
    Args:
        func_name: Name of the function being profiled
        output_file: Optional file to save profile data
        
    Yields:
        Profiler object
    """
    profiler = cProfile.Profile()
    profiler.enable()
    
    try:
        yield profiler
    finally:
        profiler.disable()
        
        if output_file:
            profiler.dump_stats(str(output_file))
        
        # Print stats to console
        stats = pstats.Stats(profiler)
        stats.sort_stats('cumulative')
        stats.print_stats(20)  # Top 20 functions


def memory_usage(func: F) -> F:
    """Decorator to track memory usage of functions.
    
    Args:
        func: Function to track
        
    Returns:
        Wrapped function with memory tracking
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tracemalloc.start()
        start_memory = tracemalloc.get_traced_memory()[0]
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            current_memory, peak_memory = tracemalloc.get_traced_memory()
            memory_used = current_memory - start_memory
            
            import logging
            logger = logging.getLogger("Performance")
            logger.info(f"{func.__name__} memory usage: {memory_used / 1024 / 1024:.2f} MB")
            logger.info(f"{func.__name__} peak memory: {peak_memory / 1024 / 1024:.2f} MB")
            
            tracemalloc.stop()
    
    return wrapper 
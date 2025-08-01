"""Logging utilities for DepShield."""

import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme


class DepShieldLogger:
    """Custom logger with rich formatting and performance tracking."""
    
    def __init__(self, name: str, level: int = logging.INFO) -> None:
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self._setup_handlers()
    
    def _setup_handlers(self) -> None:
        """Setup rich console handler with custom theme."""
        console = Console(theme=Theme({
            "info": "cyan",
            "warning": "yellow", 
            "error": "red",
            "critical": "red bold",
            "debug": "dim",
        }))
        
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
        )
        
        formatter = logging.Formatter(
            fmt="%(name)s: %(message)s",
            datefmt="[%X]"
        )
        handler.setFormatter(formatter)
        
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()
        self.logger.addHandler(handler)
        self.logger.propagate = False
    
    def info(self, msg: str, **kwargs: Any) -> None:
        """Log info message."""
        self.logger.info(msg, extra=kwargs)
    
    def warning(self, msg: str, **kwargs: Any) -> None:
        """Log warning message."""
        self.logger.warning(msg, extra=kwargs)
    
    def error(self, msg: str, **kwargs: Any) -> None:
        """Log error message."""
        self.logger.error(msg, extra=kwargs)
    
    def debug(self, msg: str, **kwargs: Any) -> None:
        """Log debug message."""
        self.logger.debug(msg, extra=kwargs)
    
    def critical(self, msg: str, **kwargs: Any) -> None:
        """Log critical message."""
        self.logger.critical(msg, extra=kwargs)


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    verbose: bool = False
) -> None:
    """Setup logging configuration for DepShield.
    
    Args:
        level: Logging level
        log_file: Optional log file path
        verbose: Enable verbose logging
    """
    if verbose:
        level = logging.DEBUG
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            *([logging.FileHandler(log_file)] if log_file else [])
        ]
    )
    
    # Set specific logger levels
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> DepShieldLogger:
    """Get a DepShield logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Configured logger instance
    """
    return DepShieldLogger(name) 
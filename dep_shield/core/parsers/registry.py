"""Plugin registry system for dependency parsers."""

from typing import Dict, List, Optional, Type, Any
from pathlib import Path
from .base import BaseParser, ParsedDependencies


class ParserRegistry:
    """Registry for dependency file parsers with plugin support."""
    
    def __init__(self) -> None:
        """Initialize the parser registry."""
        self._parsers: Dict[tuple[str, str], BaseParser] = {}
        self._ecosystem_parsers: Dict[str, List[BaseParser]] = {}
    
    def register(self, ecosystem: str, parser_type: str, parser: BaseParser) -> None:
        """Register a parser for an ecosystem and type.
        
        Args:
            ecosystem: Ecosystem name (e.g., 'python', 'nodejs')
            parser_type: Parser type (e.g., 'requirements', 'package')
            parser: Parser instance to register
        """
        key = (ecosystem, parser_type)
        self._parsers[key] = parser
        
        # Update ecosystem index
        if ecosystem not in self._ecosystem_parsers:
            self._ecosystem_parsers[ecosystem] = []
        self._ecosystem_parsers[ecosystem].append(parser)
    
    def get_parser(self, ecosystem: str, parser_type: str) -> Optional[BaseParser]:
        """Get a parser for the specified ecosystem and type.
        
        Args:
            ecosystem: Ecosystem name
            parser_type: Parser type
            
        Returns:
            Parser instance or None if not found
        """
        return self._parsers.get((ecosystem, parser_type))
    
    def get_ecosystem_parsers(self, ecosystem: str) -> List[BaseParser]:
        """Get all parsers for an ecosystem.
        
        Args:
            ecosystem: Ecosystem name
            
        Returns:
            List of parsers for the ecosystem
        """
        return self._ecosystem_parsers.get(ecosystem, [])
    
    def find_parser_for_file(self, file_path: Path) -> Optional[BaseParser]:
        """Find a parser that can handle the given file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Parser that can handle the file or None
        """
        for parser in self._parsers.values():
            if parser.can_parse(file_path):
                return parser
        return None
    
    def get_supported_ecosystems(self) -> List[str]:
        """Get list of supported ecosystems.
        
        Returns:
            List of ecosystem names
        """
        return list(self._ecosystem_parsers.keys())
    
    def get_supported_parser_types(self) -> List[str]:
        """Get list of supported parser types.
        
        Returns:
            List of parser type names
        """
        return list(set(parser_type for _, parser_type in self._parsers.keys()))
    
    def parse_file(self, file_path: Path) -> Optional[ParsedDependencies]:
        """Parse a file using the appropriate parser.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            Parsed dependencies or None if no parser found
        """
        parser = self.find_parser_for_file(file_path)
        if parser:
            return parser.parse(file_path)
        return None
    
    def parse_files(self, file_paths: List[Path]) -> List[ParsedDependencies]:
        """Parse multiple files.
        
        Args:
            file_paths: List of file paths to parse
            
        Returns:
            List of parsed dependencies
        """
        results = []
        for file_path in file_paths:
            parsed = self.parse_file(file_path)
            if parsed:
                results.append(parsed)
        return results


class ParserDecorator:
    """Decorator for registering parsers."""
    
    def __init__(self, registry: ParserRegistry, ecosystem: str, parser_type: str) -> None:
        """Initialize the decorator.
        
        Args:
            registry: Parser registry instance
            ecosystem: Ecosystem name
            parser_type: Parser type
        """
        self.registry = registry
        self.ecosystem = ecosystem
        self.parser_type = parser_type
    
    def __call__(self, parser_class: Type[BaseParser]) -> Type[BaseParser]:
        """Register the parser class.
        
        Args:
            parser_class: Parser class to register
            
        Returns:
            The original parser class
        """
        parser_instance = parser_class()
        self.registry.register(self.ecosystem, self.parser_type, parser_instance)
        return parser_class


def register_parser(ecosystem: str, parser_type: str, registry: Optional[ParserRegistry] = None) -> ParserDecorator:
    """Decorator factory for registering parsers.
    
    Args:
        ecosystem: Ecosystem name
        parser_type: Parser type
        registry: Parser registry instance (uses global registry if None)
        
    Returns:
        Decorator function
    """
    if registry is None:
        # Use global registry
        from . import registry as global_registry
        registry = global_registry
    
    return ParserDecorator(registry, ecosystem, parser_type)


class ParserDescriptor:
    """Descriptor for accessing parsers by ecosystem and type."""
    
    def __init__(self, registry: ParserRegistry) -> None:
        """Initialize the descriptor.
        
        Args:
            registry: Parser registry instance
        """
        self.registry = registry
    
    def __get__(self, obj: Any, objtype: Optional[Type] = None) -> ParserRegistry:
        """Get the registry instance.
        
        Args:
            obj: Instance object
            objtype: Class type
            
        Returns:
            Parser registry instance
        """
        return self.registry
    
    def __set__(self, obj: Any, value: ParserRegistry) -> None:
        """Set the registry instance.
        
        Args:
            obj: Instance object
            value: New registry instance
        """
        self.registry = value 
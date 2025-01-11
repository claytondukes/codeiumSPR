#!/usr/bin/env python3

import re
import datetime
import logging
import argparse
import json
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Union, Any
from pathlib import Path
from enum import Enum
import ast
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ActionType(Enum):
    """Types of actions that can occur in the chat."""
    MOD = "MOD"      # Modification
    DISC = "DISC"    # Discussion
    DOC = "DOC"      # Documentation
    VERIFY = "VERIFY" # Verification
    FIX = "FIX"      # Bug fix
    REFACTOR = "REFACTOR" # Code refactor
    TEST = "TEST"    # Testing
    CONFIG = "CONFIG" # Configuration

class ComponentType(Enum):
    """Types of system components that can be referenced."""
    API = "api"
    DATA = "data"
    DOCS = "docs"
    SCHEMA = "schema"
    BUILD = "build"
    ROUTE = "route"
    MODEL = "model"
    SERVICE = "service"

@dataclass
class FileReference:
    """Reference to a file and its associated metadata."""
    path: str
    component: ComponentType
    changes: List[str] = field(default_factory=list)
    impacts: List[str] = field(default_factory=list)

@dataclass
class ErrorTrace:
    """Details of an error occurrence."""
    type: str
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    stack: List[str] = field(default_factory=list)

@dataclass
class HistoryEntry:
    """A single entry in the chat history."""
    timestamp: str
    action_type: ActionType
    target: str
    files: List[FileReference]
    impacts: List[str]
    actions: List[str]
    error_traces: List[ErrorTrace] = field(default_factory=list)
    discussion_points: List[str] = field(default_factory=list)

@dataclass
class Context:
    """Context information for the current state."""
    focus: str
    dependencies: List[str]
    schema_version: str
    data_version: str
    issues: List[str]
    tools: List[str]
    configs: Dict[str, str]
    artifacts: List[str]

@dataclass
class CurrentState:
    """Current state of the system/conversation."""
    task: str
    state: str
    modifications: List[FileReference]
    next_steps: List[str]
    blockers: List[str]

class CodeBlockParser:
    """Parses code blocks and their context from chat messages."""
    
    def __init__(self):
        self.language_patterns = {
            'python': r'```python\n(.*?)\n```',
            'json': r'```json\n(.*?)\n```',
            'javascript': r'```javascript\n(.*?)\n```',
            'typescript': r'```typescript\n(.*?)\n```',
            'bash': r'```bash\n(.*?)\n```',
            'sql': r'```sql\n(.*?)\n```',
            # Support for inline code
            'inline': r'`([^`]+)`',
            # Support for code without language specification
            'generic': r'```\n(.*?)\n```'
        }

    def extract_code_blocks(self, text: str) -> List[Dict[str, str]]:
        """
        Extract all code blocks from text.
        
        Args:
            text: The text to parse
            
        Returns:
            List of dicts containing language, code, and position info
        """
        blocks = []
        for lang, pattern in self.language_patterns.items():
            matches = re.finditer(pattern, text, re.DOTALL)
            for match in matches:
                blocks.append({
                    'language': lang,
                    'code': match.group(1).strip(),
                    'start': match.start(),
                    'end': match.end(),
                    'full_match': match.group(0)
                })
        return sorted(blocks, key=lambda x: x['start'])

class ErrorParser:
    """Parses error traces and exception details from chat messages."""
    
    def __init__(self):
        self.error_patterns = {
            'import': r'ImportError: (.*?)(?:\n|$)',
            'type': r'TypeError: (.*?)(?:\n|$)',
            'value': r'ValueError: (.*?)(?:\n|$)',
            'attribute': r'AttributeError: (.*?)(?:\n|$)',
            'key': r'KeyError: (.*?)(?:\n|$)',
            'index': r'IndexError: (.*?)(?:\n|$)',
            'name': r'NameError: (.*?)(?:\n|$)',
            'syntax': r'SyntaxError: (.*?)(?:\n|$)',
            'runtime': r'RuntimeError: (.*?)(?:\n|$)',
            'assertion': r'AssertionError: (.*?)(?:\n|$)',
            'indentation': r'IndentationError: (.*?)(?:\n|$)',
            'os': r'OSError: (.*?)(?:\n|$)',
            'io': r'IOError: (.*?)(?:\n|$)',
            'permission': r'PermissionError: (.*?)(?:\n|$)',
            'file_not_found': r'FileNotFoundError: (.*?)(?:\n|$)',
            'module_not_found': r'ModuleNotFoundError: (.*?)(?:\n|$)',
        }
        self.file_line_pattern = r'File "([^"]+)", line (\d+)'
        self.traceback_pattern = r'Traceback \(most recent call last\):\n(.*?)(?:\n\n|$)'

    def parse_error(self, text: str) -> Optional[ErrorTrace]:
        """
        Parse error information from text.
        
        Args:
            text: The text to parse
            
        Returns:
            ErrorTrace object if an error is found, None otherwise
        """
        try:
            for error_type, pattern in self.error_patterns.items():
                match = re.search(pattern, text, re.DOTALL)
                if match:
                    error = ErrorTrace(
                        type=error_type,
                        message=match.group(1).strip()
                    )
                    
                    # Extract file and line info
                    file_match = re.search(self.file_line_pattern, text)
                    if file_match:
                        error.file = file_match.group(1)
                        error.line = int(file_match.group(2))

                    # Extract stack trace
                    trace_match = re.search(self.traceback_pattern, text, re.DOTALL)
                    if trace_match:
                        error.stack = [
                            line.strip() 
                            for line in trace_match.group(1).split('\n')
                            if line.strip()
                        ]

                    return error
                    
        except Exception as e:
            logger.warning(f"Error parsing error trace: {str(e)}")
            
        return None

class ChatLogParser:
    """Parses chat logs into structured SPR format."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.history_entries: List[HistoryEntry] = []
        self.context = None
        self.current_state = None
        self.modified_files: Dict[str, FileReference] = {}
        self.issues: Set[str] = set()
        self.start_time = None
        self.code_parser = CodeBlockParser()
        self.error_parser = ErrorParser()
        self.components: Dict[str, Set[str]] = defaultdict(set)
        
        # Regex patterns for parsing
        self.timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        self.file_patterns = [
            # Direct file paths
            r'(?:/[a-zA-Z0-9_.-]+)+\.[a-zA-Z0-9]+',
            # File references in code or logs
            r'(?:^|\s)([a-zA-Z0-9_-]+\.[a-zA-Z0-9]+)',
            # File markers
            r'@([a-zA-Z0-9_-]+\.[a-zA-Z0-9]+)',
            # Common file operations
            r'(?:edit|update|modify|create|delete)\s+([a-zA-Z0-9/_-]+\.[a-zA-Z0-9]+)',
            # Git operations
            r'(?:add|commit|push)\s+([a-zA-Z0-9/_-]+\.[a-zA-Z0-9]+)',
            # Error traces
            r'File "([^"]+)"',
            # Common prefixes
            r'(?:api|docs|data|tests)/[a-zA-Z0-9/_-]+\.[a-zA-Z0-9]+'
        ]
        
        # Common action verbs for change detection
        self.action_verbs = {
            'add': 'added',
            'remove': 'removed',
            'update': 'updated',
            'fix': 'fixed',
            'modify': 'modified',
            'implement': 'implemented',
            'refactor': 'refactored',
            'move': 'moved',
            'rename': 'renamed',
            'delete': 'deleted'
        }

    def parse_component_type(self, file_path: str) -> ComponentType:
        """
        Determine component type from file path.
        
        Args:
            file_path: Path to the file
            
        Returns:
            ComponentType enum value
        """
        if file_path.startswith('/api/'):
            if 'routes' in file_path:
                return ComponentType.ROUTE
            elif 'models' in file_path:
                return ComponentType.MODEL
            elif 'services' in file_path:
                return ComponentType.SERVICE
            return ComponentType.API
        elif file_path.startswith('/data/'):
            return ComponentType.DATA
        elif file_path.startswith('/docs/'):
            return ComponentType.DOCS
        elif 'schema' in file_path.lower():
            return ComponentType.SCHEMA
        elif 'build' in file_path.lower():
            return ComponentType.BUILD
        return ComponentType.API

    def parse_file_references(self, text: str) -> List[str]:
        """
        Extract file references from text.
        
        Args:
            text: Text to parse
            
        Returns:
            List of file paths found
        """
        files = set()
        for pattern in self.file_patterns:
            matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                # Get the full match or first group if exists
                file = match.group(1) if match.groups() else match.group(0)
                # Clean up the file path
                file = file.strip('"\'').strip()
                # Add if it looks like a valid file
                if '.' in file and not file.startswith(('.', '..', '/')):
                    files.add(file)
                elif file.startswith('/'):
                    files.add(file.lstrip('/'))
        
        return list(files)

    def extract_discussion_points(self, text: str) -> List[str]:
        """
        Extract discussion points from text.
        
        Args:
            text: Text to parse
            
        Returns:
            List of discussion points
        """
        points = []
        lines = text.split('\n')
        current_point = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(('- ', '* ', '1. ')):
                if current_point:
                    points.append(' '.join(current_point))
                current_point = [stripped[2:]]
            elif stripped and current_point:
                current_point.append(stripped)
            elif not stripped and current_point:
                points.append(' '.join(current_point))
                current_point = []
        
        if current_point:
            points.append(' '.join(current_point))
        
        return points

    def parse_dependencies(self, text: str) -> List[str]:
        """
        Extract dependencies from text.
        
        Args:
            text: Text to parse
            
        Returns:
            List of dependencies found
        """
        deps = set()
        patterns = [
            r'from\s+(\w+(?:\.\w+)*)\s+import',
            r'import\s+(\w+(?:\.\w+)*)',
            r'requires\s+(\w+(?:\.\w+)*)',
            r'depends\s+on\s+(\w+(?:\.\w+)*)',
            r'using\s+(\w+(?:\.\w+)*)',
            r'needs\s+(\w+(?:\.\w+)*)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                deps.add(match.group(1))
        
        return list(deps)

    def determine_target(self, chunk: str) -> str:
        """
        Determine the target of the action.
        
        Args:
            chunk: Text chunk to analyze
            
        Returns:
            String describing the target
        """
        # Look for specific components or systems
        component_patterns = [
            (r'(?:in|update|fix)\s+(\w+)_system', "system"),
            (r'(?:in|with)\s+(\w+)_service', "service"),
            (r'(?:in|at)\s+(\w+)_component', "component"),
            (r'(?:in|for)\s+(\w+)_manager', "manager"),
            (r'(?:update|fix)\s+(\w+)_configuration', "config"),
            (r'error\s+in\s+(\w+)', "error"),
            (r'issue\s+with\s+(\w+)', "issue"),
            (r'bug\s+in\s+(\w+)', "bug"),
            (r'refactor\s+(\w+)', "refactor"),
            (r'implement\s+(\w+)', "implement")
        ]
        
        for pattern, category in component_patterns:
            match = re.search(pattern, chunk.lower())
            if match:
                return f"{category}:{match.group(1)}"
        
        # Look for file-based targets
        file_refs = self.parse_file_references(chunk)
        if file_refs:
            return f"file:{file_refs[0]}"
        
        # Default based on content analysis
        for action in self.action_verbs:
            if action in chunk.lower():
                return f"{action}_operation"
        
        return "general_update"

    def analyze_changes(self, chunk: str, file_path: str) -> List[str]:
        """
        Analyze changes in a chunk of text.
        
        Args:
            chunk: Text chunk to analyze
            file_path: Path to the file being changed
            
        Returns:
            List of change descriptions
        """
        changes = []
        
        # Look for specific change patterns
        for verb, change_type in self.action_verbs.items():
            pattern = f"{verb}(?:ed|ing)?\\s+(\\w+)"
            matches = re.finditer(pattern, chunk, re.IGNORECASE)
            for match in matches:
                target = match.group(1)
                changes.append(f"{change_type}_{target}")
        
        # Look for code blocks that might show changes
        code_blocks = self.code_parser.extract_code_blocks(chunk)
        if code_blocks:
            for block in code_blocks:
                if '+' in block['code'] or '-' in block['code']:
                    changes.append("code_modified")
                if 'def ' in block['code']:
                    changes.append("function_modified")
                if 'class ' in block['code']:
                    changes.append("class_modified")
        
        # Look for error fixes
        if "error" in chunk.lower() or "fix" in chunk.lower():
            error = self.error_parser.parse_error(chunk)
            if error:
                changes.append(f"fixed_{error.type}")
        
        return changes if changes else ["general_update"]

    def extract_impacts(self, chunk: str) -> List[str]:
        """
        Extract impacts from a chunk of text.
        
        Args:
            chunk: Text chunk to analyze
            
        Returns:
            List of impact descriptions
        """
        impacts = []
        
        impact_patterns = {
            r'breaks?\s+(\w+)': "breaks",
            r'affects?\s+(\w+)': "affects",
            r'requires?\s+(\w+)': "requires",
            r'depends?\s+on\s+(\w+)': "depends_on",
            r'impact(?:s|ed)?\s+(\w+)': "impacts",
            r'chang(?:es|ed)?\s+(\w+)': "changes",
            r'modif(?:ies|ied)?\s+(\w+)': "modifies",
            r'needs?\s+update\s+to\s+(\w+)': "needs_update"
        }
        
        for pattern, impact_type in impact_patterns.items():
            matches = re.finditer(pattern, chunk, re.IGNORECASE)
            for match in matches:
                target = match.group(1)
                impacts.append(f"{impact_type}_{target}")
        
        # Look for dependencies
        deps = self.parse_dependencies(chunk)
        if deps:
            impacts.extend([f"depends_on_{dep}" for dep in deps])
        
        # Look for error impacts
        if "error" in chunk.lower():
            error = self.error_parser.parse_error(chunk)
            if error:
                impacts.append(f"causes_{error.type}")
        
        return impacts if impacts else ["no_significant_impact"]

    def parse_log(self):
        """Parse the entire chat log into structured format."""
        logger.info("Beginning chat log parse")
        
        try:
            # Read the entire file
            content = self.file_path.read_text()
            
            # Split into conversation chunks
            chunks = content.split("\nHuman: ")
            
            # Track the earliest timestamp we find
            self.start_time = datetime.datetime.now()
            current_entry = None
            
            for chunk_index, chunk in enumerate(chunks):
                if not chunk.strip():
                    continue
                    
                # Look for timestamps
                timestamp_matches = list(self.timestamp_pattern.finditer(chunk))
                if timestamp_matches:
                    for match in timestamp_matches:
                        timestamp = datetime.datetime.strptime(match.group(), "%Y-%m-%d %H:%M:%S")
                        if not self.start_time or timestamp < self.start_time:
                            self.start_time = timestamp
                
                # Parse any error traces
                error_traces = []
                if "Traceback" in chunk:
                    error = self.error_parser.parse_error(chunk)
                    if error:
                        error_traces.append(error)
                        self.issues.add(f"error_{error.type}")
                
                # Extract code blocks
                code_blocks = self.code_parser.extract_code_blocks(chunk)
                
                # Parse file references and changes
                file_refs = []
                for file_path in self.parse_file_references(chunk):
                    component = self.parse_component_type(file_path)
                    ref = FileReference(
                        path=file_path,
                        component=component,
                        changes=self.analyze_changes(chunk, file_path)
                    )
                    file_refs.append(ref)
                    self.modified_files[file_path] = ref
                
                # Extract discussion points
                points = self.extract_discussion_points(chunk)
                
                # Determine action type based on content
                action_type = None
                if error_traces:
                    action_type = ActionType.FIX
                elif code_blocks:
                    action_type = ActionType.MOD
                elif points:
                    action_type = ActionType.DISC
                elif "test" in chunk.lower():
                    action_type = ActionType.TEST
                else:
                    action_type = ActionType.DISC
                
                # Create history entry if we found anything interesting
                if error_traces or code_blocks or file_refs or points:
                    entry = HistoryEntry(
                        timestamp=datetime.datetime.now().strftime("%H:%M"),
                        action_type=action_type,
                        target=self.determine_target(chunk),
                        files=file_refs,
                        impacts=self.extract_impacts(chunk),
                        actions=self.parse_actions(chunk),
                        error_traces=error_traces,
                        discussion_points=points
                    )
                    self.history_entries.append(entry)
                    
                # Update components dependencies
                for ref in file_refs:
                    deps = self.parse_dependencies(chunk)
                    if deps:
                        self.components[ref.component.value].update(deps)
            
            # Create final state objects
            self._create_current_state()
            self._create_context()
            
            logger.info(f"Parsed {len(self.history_entries)} history entries")
            
        except Exception as e:
            logger.error(f"Error parsing chat log: {str(e)}")
            raise

    def parse_actions(self, chunk: str) -> List[str]:
        """
        Extract actions from a chunk of text.
        
        Args:
            chunk: Text chunk to analyze
            
        Returns:
            List of action descriptions
        """
        actions = []
        # Look for direct actions
        for verb in self.action_verbs:
            if verb in chunk.lower():
                actions.append(verb)
        
        # Look for specific patterns
        action_patterns = [
            (r'need(?:s)? to (\w+)', 'needs'),
            (r'should (\w+)', 'should'),
            (r'must (\w+)', 'must'),
            (r'will (\w+)', 'will'),
            (r'going to (\w+)', 'planned')
        ]
        
        for pattern, action_type in action_patterns:
            matches = re.finditer(pattern, chunk.lower())
            for match in matches:
                actions.append(f"{action_type}_{match.group(1)}")
        
        return actions if actions else ["no_explicit_action"]

    def _create_current_state(self):
        """Create the current state object from parsed data."""
        # Determine main task from history
        if self.history_entries:
            latest_entry = max(self.history_entries, key=lambda x: x.timestamp)
            main_task = latest_entry.target
        else:
            main_task = "system_review"

        # Determine next steps based on recent history
        next_steps = set()
        for entry in self.history_entries[-3:]:  # Look at last 3 entries
            for action in entry.actions:
                if action.startswith(('needs_', 'should_', 'must_', 'will_')):
                    next_steps.add(action)

        # Determine blockers from errors and dependencies
        blockers = []
        for issue in self.issues:
            if "error" in issue or "missing" in issue:
                blockers.append(issue)

        self.current_state = CurrentState(
            task=main_task,
            state="in_progress" if self.issues else "ready",
            modifications=list(self.modified_files.values()),
            next_steps=list(next_steps) or ["verify_changes", "update_docs", "run_tests"],
            blockers=blockers
        )

    def _create_context(self):
        """Create the context object from parsed data."""
        # Determine focus from history
        focus_counts = defaultdict(int)
        for entry in self.history_entries:
            if entry.target != "general":
                focus_counts[entry.target.split(':')[0]] += 1
        
        main_focus = max(focus_counts.items(), key=lambda x: x[1])[0] if focus_counts else "system_maintenance"

        # Collect all dependencies
        all_deps = set()
        for deps in self.components.values():
            all_deps.update(deps)

        # Collect tools from code blocks and discussion
        tools = {"git", "python3"}  # Basic defaults
        for entry in self.history_entries:
            for block in self.code_parser.extract_code_blocks('\n'.join(entry.discussion_points)):
                if block['language'] not in tools:
                    tools.add(block['language'])

        # Build configs dict
        configs = {
            "schema_version": "1.0.0",
            "data_version": "1.0.0"
        }
        for file_ref in self.modified_files.values():
            if file_ref.component == ComponentType.CONFIG:
                configs[file_ref.path] = "modified"

        self.context = Context(
            focus=main_focus,
            dependencies=list(all_deps),
            schema_version=configs["schema_version"],
            data_version=configs["data_version"],
            issues=list(self.issues),
            tools=list(tools),
            configs=configs,
            artifacts=self._collect_artifacts()
        )

    def _collect_artifacts(self) -> List[str]:
        """Collect all artifacts mentioned in the chat."""
        artifacts = set()
        for entry in self.history_entries:
            for point in entry.discussion_points:
                if 'artifact' in point.lower():
                    # Look for artifact types or references
                    matches = re.finditer(r'(?:artifact|file) [\'"]*([^\'"]+)[\'"]*', point, re.IGNORECASE)
                    for match in matches:
                        artifacts.add(match.group(1))
        return list(artifacts)

    def generate_spr(self) -> str:
        """
        Generate SPR format output from parsed data.
        
        Returns:
            String containing the complete SPR representation
        """
        if not self.context or not self.current_state:
            raise ValueError("Must parse_log() before generating SPR")
            
        output = []
        
        # Header with full ISO timestamp
        output.append(f"#T:{self.start_time.isoformat()}")
        output.append("#S:COMPREHENSIVE_SYSTEM_REFACTOR")
        output.append("#P:CRITICAL")
        output.append("")

        # Detailed history entries
        for entry in sorted(self.history_entries, key=lambda x: x.timestamp):
            output.append(f"@H[{entry.timestamp}]{entry.action_type.value}>{entry.target}{{")
            
            # Files with their components and changes
            if entry.files:
                output.append("  F:[")
                for file_ref in entry.files:
                    changes = ','.join(file_ref.changes) if file_ref.changes else 'no_changes'
                    output.append(f"    {file_ref.path}:{file_ref.component.value}:{changes}")
                output.append("  ]")
            
            # Impacts and actions
            if entry.impacts:
                output.append(f"  I:[{','.join(entry.impacts)}]")
            if entry.actions:
                output.append(f"  A:[{','.join(entry.actions)}]")
                
            # Error traces if any
            if entry.error_traces:
                output.append("  E:[")
                for error in entry.error_traces:
                    output.append(f"    {error.type}:{error.message}")
                    if error.file:
                        output.append(f"    at {error.file}:{error.line}")
                    if error.stack:
                        output.append("    stack:[")
                        for frame in error.stack:
                            output.append(f"      {frame}")
                        output.append("    ]")
                output.append("  ]")
                
            # Discussion points if any
            if entry.discussion_points:
                output.append("  D:[")
                for point in entry.discussion_points:
                    output.append(f"    {point}")
                output.append("  ]")
                
            output.append("}")
            output.append("")

        # Current state
        output.append("@CUR{")
        output.append(f"  TASK:{self.current_state.task}")
        output.append(f"  STATE:{self.current_state.state}")
        output.append("  MODS:[")
        for file_ref in self.current_state.modifications:
            output.append(f"    {file_ref.path}:{file_ref.component.value}")
        output.append("  ]")
        output.append(f"  NEXT:[{','.join(self.current_state.next_steps)}]")
        if self.current_state.blockers:
            output.append(f"  BLOCKERS:[{','.join(self.current_state.blockers)}]")
        output.append("}")

        # Context
        output.append("")
        output.append("@CTX{")
        output.append(f"  FOCUS:{self.context.focus}")
        output.append(f"  DEPS:[{','.join(self.context.dependencies)}]")
        output.append(f"  SCHEMA_V:{self.context.schema_version}")
        output.append(f"  DATA_V:{self.context.data_version}")
        output.append(f"  ISSUES:[{','.join(self.context.issues)}]")
        output.append(f"  TOOLS:[{','.join(self.context.tools)}]")
        output.append("  CONFIGS:{")
        for k, v in self.context.configs.items():
            output.append(f"    {k}:{v}")
        output.append("  }")
        if self.context.artifacts:
            output.append(f"  ARTIFACTS:[{','.join(self.context.artifacts)}]")
        output.append("}")

        # Component dependencies
        if self.components:
            output.append("")
            output.append("@COMPONENTS{")
            for component, deps in self.components.items():
                if deps:  # Only show components with dependencies
                    output.append(f"  {component}:[{','.join(deps)}]")
            output.append("}")

        return "\n".join(output)

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Convert chat logs to SPR (Sparse Priming Representation) format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  %(prog)s chat_history.txt
  %(prog)s chat_history.txt -o custom_output.spr
  %(prog)s chat_history.txt -v
        """
    )
    parser.add_argument(
        'input_file',
        type=str,
        help='Path to the input chat log file'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Path to the output SPR file (default: input_file_spr.txt)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with additional output'
    )

    args = parser.parse_args()

    # Configure logging based on arguments
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        input_path = Path(args.input_file)
        if not input_path.exists():
            logger.error(f"Input file not found: {input_path}")
            return 1

        # Determine output path
        output_path = args.output
        if output_path is None:
            output_path = input_path.with_suffix('.spr.txt')
        output_path = Path(output_path)

        # Create output directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Processing {input_path}")
        logger.info(f"Output will be written to {output_path}")

        # Parse and generate SPR
        chat_parser = ChatLogParser(str(input_path))
        chat_parser.parse_log()
        spr = chat_parser.generate_spr()
        
        # Write output
        output_path.write_text(spr)
        logger.info(f"Successfully generated SPR format at {output_path}")
        
        if args.debug:
            # Print some statistics in debug mode
            logger.debug(f"Found {len(chat_parser.history_entries)} history entries")
            logger.debug(f"Found {len(chat_parser.modified_files)} modified files")
            logger.debug(f"Found {len(chat_parser.issues)} issues")
            logger.debug(f"Found {len(chat_parser.components)} components")
        
        return 0
            
    except Exception as e:
        logger.error(f"Error processing chat log: {str(e)}")
        if args.debug:
            logger.exception("Detailed error trace:")
        return 1

if __name__ == "__main__":
    exit(main())

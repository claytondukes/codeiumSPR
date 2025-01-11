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
import copy

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
    CONFIG = "config"

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

@dataclass
class ContextBlock:
    """AI-optimized context block for session understanding."""
    timestamp: str
    session_type: str
    main_issue: str
    core_problems: List[str]
    solution_approaches: List[str]
    key_files: Dict[str, List[str]]  # file -> [changes]
    dependencies: Dict[str, List[str]]  # component -> [dependencies]
    reasoning_chain: List[Dict[str, Any]]  # List of {action, reason, result}
    state_changes: Dict[str, Any]  # Track important state changes
    error_context: Dict[str, List[str]]  # error_type -> [relevant_context]

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
    """Parses chat logs into structured SPR format optimized for AI consumption."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.context_blocks: List[ContextBlock] = []
        self.current_block = None
        self.code_parser = CodeBlockParser()
        self.error_parser = ErrorParser()
        
        # Enhanced patterns for AI context extraction
        self.issue_patterns = [
            r'(?:error|issue|problem|bug).*?:\s*(.*?)(?:\n|$)',
            r'(?:fails?|breaks?|doesn\'t work).*?(?:because|when|if)\s*(.*?)(?:\n|$)',
            r'(?:need|should|must)\s+(?:to\s+)?(?:fix|resolve|address)\s*(.*?)(?:\n|$)'
        ]
        self.solution_patterns = [
            r'(?:fix|solve|resolve)\s+(?:this|the|that)\s+by\s*(.*?)(?:\n|$)',
            r'(?:let|going|need)\s+(?:me|to)\s*(?:try|implement|add|update)\s*(.*?)(?:\n|$)',
            r'(?:solution|approach|fix)\s+(?:is|would be)\s+to\s*(.*?)(?:\n|$)'
        ]
        self.reasoning_patterns = [
            r'(?:because|since|as)\s*(.*?)(?:\n|$)',
            r'(?:this|that|it)\s+(?:means|implies|suggests)\s*(.*?)(?:\n|$)',
            r'(?:the|this|that)\s+(?:leads to|results in|causes)\s*(.*?)(?:\n|$)'
        ]

    def parse_log(self):
        """Parse the chat log into AI-optimized context blocks."""
        with open(self.file_path, 'r') as f:
            content = f.read()
            
        # Split into logical blocks based on context shifts
        blocks = self._split_into_context_blocks(content)
        
        for block in blocks:
            context = ContextBlock(
                timestamp=self._extract_timestamp(block),
                session_type=self._infer_session_type(block),
                main_issue=self._extract_main_issue(block),
                core_problems=self._extract_core_problems(block),
                solution_approaches=self._extract_solutions(block),
                key_files=self._extract_file_changes(block),
                dependencies=self._extract_dependencies(block),
                reasoning_chain=self._extract_reasoning_chain(block),
                state_changes=self._extract_state_changes(block),
                error_context=self._extract_error_context(block)
            )
            self.context_blocks.append(context)

    def generate_spr(self) -> str:
        """Generate AI-optimized SPR format."""
        output = []
        
        for block in self.context_blocks:
            # Metadata section
            output.append(f"#T:{block.timestamp}")
            output.append(f"#S:{block.session_type}")
            output.append(f"#I:{block.main_issue}")
            
            # Consolidate problems and link solutions
            consolidated_problems = self._consolidate_problems(block.core_problems)
            linked_problems = self._link_solutions_to_problems(
                consolidated_problems, 
                block.solution_approaches
            )
            
            # Core problems and solutions with reasoning
            output.append("@CONTEXT{")
            output.append(json.dumps({
                'issues': linked_problems,
                'reasoning': block.reasoning_chain
            }, indent=2))
            output.append("}")
            
            # File changes with semantic meaning
            if block.key_files:
                output.append("@CHANGES{")
                output.append(json.dumps(block.key_files, indent=2))
                output.append("}")
            
            # Dependencies and state changes
            if block.dependencies or block.state_changes:
                output.append("@STATE{")
                state_info = {}
                if block.dependencies:
                    state_info['dependencies'] = block.dependencies
                if block.state_changes:
                    state_info['changes'] = block.state_changes
                output.append(json.dumps(state_info, indent=2))
                output.append("}")
            
            # Error context if present
            if block.error_context:
                output.append("@ERRORS{")
                # Organize discussion points
                organized = self._organize_discussion(
                    block.error_context.get('discussion', [])
                )
                output.append(json.dumps({
                    **block.error_context,
                    'discussion': organized
                }, indent=2))
                output.append("}")
            
            output.append("")  # Block separator
        
        return "\n".join(output)

    def _split_into_context_blocks(self, content: str) -> List[str]:
        """Split content into logical blocks based on context shifts."""
        blocks = []
        current_block = []
        
        # Split on Human/Assistant markers and major section headers
        lines = content.split('\n')
        for line in lines:
            # New context indicators
            if (line.startswith(('Human:', 'Assistant:', '## ', '# ')) or 
                re.match(r'^[A-Z][a-z]+ \d{1,2}, \d{4}', line)):
                if current_block:
                    blocks.append('\n'.join(current_block))
                    current_block = []
            current_block.append(line)
            
        # Add final block
        if current_block:
            blocks.append('\n'.join(current_block))
            
        # Merge small blocks that are likely part of the same context
        merged_blocks = []
        temp_block = []
        for block in blocks:
            if len(block.split('\n')) < 5 and temp_block:  # Small block
                temp_block.append(block)
            else:
                if temp_block:
                    merged_blocks.append('\n'.join(temp_block))
                    temp_block = []
                temp_block.append(block)
                
        if temp_block:
            merged_blocks.append('\n'.join(temp_block))
            
        return merged_blocks

    def _extract_timestamp(self, block: str) -> str:
        """Extract timestamp from block."""
        # Look for ISO format timestamps
        iso_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2})?'
        if match := re.search(iso_pattern, block):
            return match.group(0)
            
        # Look for common date/time formats
        patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\w+ \d{1,2}, \d{4} \d{1,2}:\d{2} (?:AM|PM)',
        ]
        
        for pattern in patterns:
            if match := re.search(pattern, block):
                # Convert to ISO format
                dt = datetime.datetime.strptime(match.group(0), "%Y-%m-%d %H:%M:%S")
                return dt.isoformat()
                
        # Default to current time if no timestamp found
        return datetime.datetime.now().isoformat()

    def _infer_session_type(self, block: str) -> str:
        """Infer the type of development session."""
        # Look for explicit indicators
        type_indicators = {
            'DEBUG': ['error', 'bug', 'fix', 'issue', 'problem', 'traceback'],
            'FEATURE': ['implement', 'add', 'create', 'new feature'],
            'REFACTOR': ['refactor', 'improve', 'optimize', 'clean', 'restructure'],
            'TEST': ['test', 'verify', 'validate', 'check'],
            'DOCS': ['document', 'explain', 'clarify', 'readme'],
            'CONFIG': ['configure', 'setup', 'install', 'environment'],
        }
        
        block_lower = block.lower()
        for session_type, indicators in type_indicators.items():
            if any(ind in block_lower for ind in indicators):
                return session_type
                
        # Look for code modifications
        if '```' in block or 'def ' in block or 'class ' in block:
            return 'CODE_MOD'
            
        return 'GENERAL'

    def _extract_main_issue(self, block: str) -> str:
        """Extract the main issue being discussed."""
        # First look for explicit issue statements
        for pattern in self.issue_patterns:
            if match := re.search(pattern, block, re.IGNORECASE):
                return match.group(1).strip()
                
        # Look for error traces
        if 'Traceback' in block or 'Error:' in block:
            if error_match := re.search(r'(?:Traceback.*?|Error:)(.*?)(?=\n\w|$)', block, re.DOTALL):
                return error_match.group(1).strip()
                
        # Look for task/goal statements
        task_patterns = [
            r'(?:need|want|trying) to\s+(.*?)(?:\.|$)',
            r'(?:goal|task) is to\s+(.*?)(?:\.|$)',
            r'(?:working on|implementing)\s+(.*?)(?:\.|$)'
        ]
        
        for pattern in task_patterns:
            if match := re.search(pattern, block, re.IGNORECASE):
                return match.group(1).strip()
                
        return ""

    def _extract_core_problems(self, block: str) -> List[str]:
        """Extract core problems identified in the discussion."""
        problems = []
        
        # Look for explicit problem statements
        for pattern in self.issue_patterns:
            matches = re.finditer(pattern, block, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                problem = match.group(1).strip()
                if len(problem) > 10:  # Filter out too short matches
                    problems.append(problem)
                    
        # Look for error traces
        error_pattern = r'(?:Traceback.*?(?=\n\w|$)|Error:.*?(?=\n\w|$))'
        if matches := re.finditer(error_pattern, block, re.DOTALL):
            for match in matches:
                error = match.group(0).split('\n')[0]  # Get first line of traceback
                problems.append(error)
                
        # Look for "needs to" statements
        needs_pattern = r'needs? to (?:be )?(.*?)(?:\.|$)'
        if matches := re.finditer(needs_pattern, block, re.IGNORECASE):
            for match in matches:
                problems.append(f"Needs {match.group(1)}")
                
        return list(set(problems))  # Remove duplicates

    def _extract_solutions(self, block: str) -> List[str]:
        """Extract proposed solutions and approaches."""
        solutions = []
        
        # Look for explicit solution patterns
        for pattern in self.solution_patterns:
            matches = re.finditer(pattern, block, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                solution = match.group(1).strip()
                if len(solution) > 10:  # Filter out too short matches
                    solutions.append(solution)
                    
        # Look for code blocks that implement solutions
        code_blocks = re.finditer(r'```.*?\n(.*?)```', block, re.DOTALL)
        for block_match in code_blocks:
            code = block_match.group(1)
            # Extract function/class definitions as solutions
            if def_match := re.search(r'def (\w+)', code):
                solutions.append(f"Implement {def_match.group(1)} function")
            if class_match := re.search(r'class (\w+)', code):
                solutions.append(f"Create {class_match.group(1)} class")
                
        return list(set(solutions))  # Remove duplicates

    def _extract_file_changes(self, block: str) -> Dict[str, List[str]]:
        """Extract file changes with semantic meaning."""
        changes = {}
        
        # Look for file paths and associated changes
        file_patterns = [
            r'(?:in|update|modify|create|edit)\s+`?([/\w.-]+\.[/\w.-]+)`?',
            r'(?:file|path):\s*`?([/\w.-]+\.[/\w.-]+)`?',
            r'(?:^|\s)`?([/\w.-]+\.[/\w.-]+)`?:\s*\w+',
        ]
        
        for pattern in file_patterns:
            matches = re.finditer(pattern, block, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                file_path = match.group(1)
                if file_path not in changes:
                    changes[file_path] = []
                    
                # Look for associated changes in surrounding context
                context = block[max(0, match.start() - 100):min(len(block), match.end() + 100)]
                
                # Extract change types
                change_types = []
                if 'add' in context.lower() or 'create' in context.lower():
                    change_types.append('added')
                if 'update' in context.lower() or 'modify' in context.lower():
                    change_types.append('modified')
                if 'remove' in context.lower() or 'delete' in context.lower():
                    change_types.append('removed')
                if 'fix' in context.lower():
                    change_types.append('fixed')
                    
                changes[file_path].extend(change_types)
                
        return changes

    def _extract_dependencies(self, block: str) -> Dict[str, List[str]]:
        """Extract component dependencies."""
        deps = {}
        
        # Look for import statements in code blocks
        code_blocks = re.finditer(r'```.*?\n(.*?)```', block, re.DOTALL)
        for block_match in code_blocks:
            code = block_match.group(1)
            # Extract imports
            imports = re.finditer(r'(?:from|import)\s+([\w.]+)(?:\s+import\s+)?', code)
            for imp in imports:
                module = imp.group(1)
                if '.' in module:
                    parent = module.split('.')[0]
                    if parent not in deps:
                        deps[parent] = []
                    deps[parent].append(module)
                else:
                    if 'external' not in deps:
                        deps['external'] = []
                    deps['external'].append(module)
                    
        # Look for dependency mentions in text
        dep_patterns = [
            r'depends? on\s+`?([\w.]+)`?',
            r'requires?\s+`?([\w.]+)`?',
            r'using\s+`?([\w.]+)`?',
        ]
        
        for pattern in dep_patterns:
            matches = re.finditer(pattern, block, re.IGNORECASE)
            for match in matches:
                dep = match.group(1)
                if 'mentioned' not in deps:
                    deps['mentioned'] = []
                deps['mentioned'].append(dep)
                
        return deps

    def _extract_reasoning_chain(self, block: str) -> List[Dict[str, Any]]:
        """Extract the chain of reasoning in the discussion."""
        chain = []
        
        # Look for cause-effect relationships
        for pattern in self.reasoning_patterns:
            matches = re.finditer(pattern, block, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                reasoning = match.group(1).strip()
                # Look for action and result in surrounding context
                context = block[max(0, match.start() - 100):min(len(block), match.end() + 100)]
                
                # Try to identify action and result
                action = ""
                if action_match := re.search(r'(?:will|should|must|going to)\s+(.*?)(?:\s+because|\s+since|$)', context):
                    action = action_match.group(1)
                    
                result = ""
                if result_match := re.search(r'(?:this will|resulting in|leads to)\s+(.*?)(?:\.|$)', context):
                    result = result_match.group(1)
                    
                if action or result:
                    chain.append({
                        "action": action or "unspecified",
                        "reason": reasoning,
                        "result": result or "unspecified"
                    })
                    
        return chain

    def _extract_state_changes(self, block: str) -> Dict[str, Any]:
        """Extract important state changes."""
        changes = {}
        
        # Look for state change indicators
        state_patterns = {
            'status': r'status(?:\s+is|\s+changed\s+to)?\s+`?([\w_]+)`?',
            'phase': r'phase(?:\s+is|\s+moved\s+to)?\s+`?([\w_]+)`?',
            'version': r'version(?:\s+is|\s+updated\s+to)?\s+`?([\w.]+)`?',
            'config': r'config(?:\s+is|\s+set\s+to)?\s+`?([\w_]+)`?',
        }
        
        for key, pattern in state_patterns.items():
            if match := re.search(pattern, block, re.IGNORECASE):
                changes[key] = match.group(1)
                
        # Look for variable assignments in code
        code_blocks = re.finditer(r'```.*?\n(.*?)```', block, re.DOTALL)
        for block_match in code_blocks:
            code = block_match.group(1)
            assignments = re.finditer(r'(\w+)\s*=\s*([^;\n]+)', code)
            for assign in assignments:
                var, value = assign.groups()
                if var.isupper():  # Likely a constant/config
                    changes[f"code_{var.lower()}"] = value.strip()
                    
        return changes

    def _extract_error_context(self, block: str) -> Dict[str, List[str]]:
        """Extract error context and related information."""
        context = {}
        
        # Look for error traces
        if 'Traceback' in block or 'Error:' in block:
            traces = re.finditer(r'(?:Traceback.*?(?=\n\w|$)|Error:.*?(?=\n\w|$))', block, re.DOTALL)
            for trace in traces:
                error_text = trace.group(0)
                
                # Extract error type
                if type_match := re.search(r'(\w+Error):', error_text):
                    error_type = type_match.group(1)
                    if error_type not in context:
                        context[error_type] = []
                        
                    # Extract relevant lines
                    lines = error_text.split('\n')
                    context[error_type].extend([
                        line.strip() for line in lines 
                        if line.strip() and not line.startswith(' ')
                    ])
                    
                    # Look for file references
                    files = re.finditer(r'File "([^"]+)", line (\d+)', error_text)
                    for file_match in files:
                        context[error_type].append(f"In {file_match.group(1)}:{file_match.group(2)}")
                        
        # Look for error-related discussion
        error_discussion = re.finditer(r'(?:error|issue|bug|problem).*?:\s*(.*?)(?:\n|$)', block, re.IGNORECASE)
        for disc in error_discussion:
            if 'discussion' not in context:
                context['discussion'] = []
            context['discussion'].append(disc.group(1).strip())
            
        return context

    def _consolidate_problems(self, problems: List[str]) -> List[Dict[str, Any]]:
        """Consolidate similar problems into higher-level issues with context."""
        # First group by root cause
        root_causes = {
            'import': {
                'pattern': r'(?:import|from)\s+([^\s]+)',
                'problems': [],
                'affected_modules': set()
            },
            'initialization': {
                'pattern': r'(?:init|create|setup)\s+([^\s]+)',
                'problems': [],
                'affected_components': set()
            },
            'validation': {
                'pattern': r'(?:valid|schema|type)\s+([^\s]+)',
                'problems': [],
                'affected_fields': set()
            },
            'undefined': {
                'pattern': r'name\s+\'([^\']+)\'\s+is not defined',
                'problems': [],
                'missing_names': set()
            },
            'attribute': {
                'pattern': r'has no attribute\s+\'([^\']+)\'',
                'problems': [],
                'missing_attrs': set()
            },
            'other': {
                'pattern': None,
                'problems': [],
                'context': set()
            }
        }
        
        # Categorize each problem
        for problem in problems:
            problem = problem.strip()
            if not problem:
                continue
                
            matched = False
            for category, info in root_causes.items():
                if category == 'other':
                    continue
                    
                if matches := re.finditer(info['pattern'], problem, re.IGNORECASE):
                    for match in matches:
                        matched = True
                        info['problems'].append(problem)
                        if category == 'import':
                            info['affected_modules'].add(match.group(1))
                        elif category == 'initialization':
                            info['affected_components'].add(match.group(1))
                        elif category == 'validation':
                            info['affected_fields'].add(match.group(1))
                        elif category == 'undefined':
                            info['missing_names'].add(match.group(1))
                        elif category == 'attribute':
                            info['missing_attrs'].add(match.group(1))
            
            if not matched:
                root_causes['other']['problems'].append(problem)
        
        # Convert to final format
        consolidated = []
        for category, info in root_causes.items():
            if not info['problems']:
                continue
                
            issue = {
                'type': category,
                'summary': self._generate_summary(category, info),
                'details': list(set(info['problems'])),  # Remove duplicates
                'context': {}
            }
            
            # Add category-specific context
            if category == 'import':
                issue['context']['modules'] = list(info['affected_modules'])
            elif category == 'initialization':
                issue['context']['components'] = list(info['affected_components'])
            elif category == 'validation':
                issue['context']['fields'] = list(info['affected_fields'])
            elif category == 'undefined':
                issue['context']['names'] = list(info['missing_names'])
            elif category == 'attribute':
                issue['context']['attributes'] = list(info['missing_attrs'])
            elif category == 'other':
                issue['context']['general'] = list(info['context'])
            
            consolidated.append(issue)
            
        return consolidated

    def _generate_summary(self, category: str, info: Dict[str, Any]) -> str:
        """Generate a concise summary of the issue category."""
        if category == 'import':
            modules = ', '.join(info['affected_modules'])
            return f"Import issues with modules: {modules}"
        elif category == 'initialization':
            components = ', '.join(info['affected_components'])
            return f"Initialization issues in components: {components}"
        elif category == 'validation':
            fields = ', '.join(info['affected_fields'])
            return f"Validation issues with fields: {fields}"
        elif category == 'undefined':
            names = ', '.join(info['missing_names'])
            return f"Undefined names: {names}"
        elif category == 'attribute':
            attrs = ', '.join(info['missing_attrs'])
            return f"Missing attributes: {attrs}"
        else:
            return "Other issues found"

    def _link_solutions_to_problems(self, problems: List[Dict[str, Any]], solutions: List[str]) -> List[Dict[str, Any]]:
        """Link solutions to their corresponding problems."""
        linked_problems = copy.deepcopy(problems)
        
        for problem in linked_problems:
            problem['solutions'] = []
            problem_text = ' '.join([problem['summary']] + problem['details']).lower()
            
            for solution in solutions:
                # Look for solutions that mention the problem's context
                if any(word.lower() in solution.lower() for word in problem['context'].get('modules', [])):
                    problem['solutions'].append(solution)
                elif any(word.lower() in solution.lower() for word in problem['context'].get('components', [])):
                    problem['solutions'].append(solution)
                elif any(word.lower() in solution.lower() for word in problem['context'].get('fields', [])):
                    problem['solutions'].append(solution)
                elif any(word.lower() in solution.lower() for word in problem['context'].get('names', [])):
                    problem['solutions'].append(solution)
                elif any(word.lower() in solution.lower() for word in problem['context'].get('attributes', [])):
                    problem['solutions'].append(solution)
                # Look for solutions that mention keywords from the problem
                elif any(word in solution.lower() for word in problem_text.split()):
                    problem['solutions'].append(solution)
        
        return linked_problems

    def _organize_discussion(self, points: List[str]) -> Dict[str, List[str]]:
        """Organize discussion points into categories."""
        organized = {
            'analysis': [],
            'changes': [],
            'errors': [],
            'solutions': [],
            'verifications': []
        }
        
        for point in points:
            point = point.strip()
            # Skip empty or uninformative points
            if not point or point in ['Analyzed', 'Edited', 'Edit:', 'CopyInsert']:
                continue
                
            # Categorize based on content
            if any(word in point.lower() for word in ['error', 'exception', 'fail']):
                organized['errors'].append(point)
            elif any(word in point.lower() for word in ['update', 'change', 'modify']):
                organized['changes'].append(point)
            elif any(word in point.lower() for word in ['fix', 'solve', 'resolve']):
                organized['solutions'].append(point)
            elif any(word in point.lower() for word in ['check', 'verify', 'test']):
                organized['verifications'].append(point)
            else:
                organized['analysis'].append(point)
        
        # Remove empty categories
        return {k: v for k, v in organized.items() if v}

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
            logger.debug(f"Found {len(chat_parser.context_blocks)} context blocks")
        
        return 0
            
    except Exception as e:
        logger.error(f"Error processing chat log: {str(e)}")
        if args.debug:
            logger.exception("Detailed error trace:")
        return 1

if __name__ == "__main__":
    exit(main())

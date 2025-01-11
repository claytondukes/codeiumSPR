# Chat Log compressor for Windsurf

This script is used to take long chat histories from Windsurf and convert that to a condensed file that can be used on new sessions with Windsurf to continue working and maintain context between sessions.

## Usage:

1. Copy all text in your chat session with Windsurf and paste in into a file
2. Run this script against it

## Example

### Legend

```
#T: Timestamp markers
#S: Session type
#P: Priority level
@H: History entries with compact timestamps
@CUR: Current state block
@CTX: Context block with dependencies
```

### Sample Input

```
I'll help you check the error log. Let me take a look at the contents of err.txt to understand what issues you're experiencing.

Analyzed

err.txt:(1-200)
I see the error. There's an issue with the BuildService initialization. The error occurs because the GameDataManager class doesn't have a load_data method that's being called during initialization. Let me check the relevant code to help fix this.

Searched codebase

51 results
Let me check the GameDataManager class to understand why the load_data method is missing.

Searched codebase

77 results
I see the issue now. There are two different GameDataManager classes in the codebase:

One in /api/models/game_data/data_manager.py with a load_data_files method
Another in /api/models/game_data/manager.py with async data loading via get_data and _reload_data
The error occurs because the BuildService is trying to use the older synchronous load_data method, but it's getting an instance of the newer async version of GameDataManager.

Let me help you fix this by updating the BuildService to use the correct async data loading pattern.

Edit:
service.py
+4
-3
1917
Preview
Apply
{{ ... }}
    def __init__(self, settings: Settings):
        """Initialize the build service.
        
        Args:
            settings
```


### Sample Output

```
#T:2025-01-11T11:39:31-05:00
#S:SCHEMA_VALIDATION
#P:HIGH

@H[10:45]DOC/init>stat_boosts.md
@H[11:20]DISC>essences_separate{/data/indexed/classes/*/essences.json}
@H[11:24]MOD>rm_essence_refs{
  F:/data/indexed/gems/stat_boosts.json
  F:/api/models/game_data/schemas/stats.py
  F:/api/models/game_data/schemas.py
  A:rm_empty_arrays,rm_schema_fields
}
@H[11:26]DOC/update>stat_boosts.md{
  A:clarify_separation,add_categories
}
@H[11:28]DOC/fix>stat_boosts.md{
  A:restore_json_comments,improve_readability
}
@H[11:37]DISC>mothers_lament_incorrect{
  I:health_threshold_only_rank10,
  A:fixed_example_in_docs
}

@CUR{
  TASK:schema_validation
  STATE:in_progress
  MODS:[
    docs/game/stat_boosts.md
    data/indexed/gems/stat_boosts.json
    api/models/game_data/schemas/stats.py
    api/models/game_data/schemas.py
  ]
  NEXT:[
    verify_indexed_data
    check_essence_refs
    update_related_docs
  ]
}

@CTX{
  FOCUS:data_integrity
  DEPS:[stats,essences,gems]
  SCHEMA_V:1.0.0
  ISSUES:[
    mothers_lament_incorrect_conditions,
    essence_stat_separation_needed
  ]
}
```


## Overview

The script processes chat logs and generates an SPR format that includes:
- Timestamps and session metadata
- History of actions and changes
- File modifications and their impacts
- Error traces and discussion points
- System state and context
- Component dependencies

## Installation

### Requirements
- Python 3.8 or higher
- No external dependencies required (uses standard library only)

### Setup
1. Clone this repository or download `txt2spr.py`
2. Make the script executable:
   ```bash
   chmod +x txt2spr.py
   ```

## Usage

Basic usage:
```bash
./txt2spr.py chat_history.txt
```

Options:
```bash
./txt2spr.py [-h] [-o OUTPUT] [-v] [--debug] input_file
```

Arguments:
- `input_file`: Path to the input chat log file
- `-o, --output`: Path to the output SPR file (default: input_file_spr.txt)
- `-v, --verbose`: Enable verbose logging
- `--debug`: Enable debug mode with additional output
- `-h, --help`: Show help message

## Input Format

The script expects a chat log file with conversations in the format:

```
Human: message
Assistant: response
Human: message
Assistant: response
...
```

## Output Format

The generated SPR format follows this structure:

```
#T:2025-01-11T16:30:00-05:00    # Timestamp
#S:SYSTEM_REFACTOR              # Session type
#P:CRITICAL                     # Priority level

@H[10:15]MOD>target{           # History entry
  F:[                          # Files modified
    path:component:changes
  ]
  I:[impacts]                  # Impacts
  A:[actions]                  # Actions
  E:[error_traces]             # Errors
  D:[discussion_points]        # Discussion
}

@CUR{                          # Current state
  TASK:current_task
  STATE:current_state
  MODS:[modifications]
  NEXT:[next_steps]
  BLOCKERS:[blockers]
}

@CTX{                          # Context
  FOCUS:main_focus
  DEPS:[dependencies]
  SCHEMA_V:version
  DATA_V:version
  ISSUES:[issues]
  TOOLS:[tools]
  CONFIGS:{configs}
  ARTIFACTS:[artifacts]
}

@COMPONENTS{                    # Component dependencies
  component:[dependencies]
}
```

## Examples

1. Basic conversion:
```bash
./txt2spr.py chat.txt
```

2. Custom output file with verbose logging:
```bash
./txt2spr.py chat.txt -o output.spr -v
```

3. Debug mode:
```bash
./txt2spr.py chat.txt --debug
```

## Components

The script consists of several key components:

1. **ChatLogParser**: Main parser class that processes the chat log
2. **CodeBlockParser**: Extracts and analyzes code blocks
3. **ErrorParser**: Parses error traces and exceptions
4. **Various Data Classes**:

   - FileReference: Tracks file changes
   - ErrorTrace: Stores error information
   - HistoryEntry: Records chat history entries
   - Context: Maintains system context
   - CurrentState: Tracks current state

## Error Handling

The script handles various error conditions:
- Missing input files
- Invalid file formats
- Parsing errors
- Output directory issues

Error messages are logged appropriately based on verbosity level.

## Limitations

- Limited to single-file processing
- May not capture complex code relationships
- Timestamp detection relies on specific format


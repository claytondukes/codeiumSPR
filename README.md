# codeiumSPR

Because AI Assistants Shouldn't Have Goldfish Memory

A specialized tool for optimizing chat history context in Windsurf IDE.

This tool processes chat logs into a Semantic Parsing Record
(SPR) format, enabling better context retention and understanding across coding
sessions.

`<not_really_an_ad>`

## Hey Kids!

Ever had your AI coding assistant forget what you were working on faster than 
you forget your keys? Say hello to codeiumSPR :)

Using my super-duper-not-a-pooper-scooper Semantic Parsing Record (SPR) script, 
you can:

- Bring the agent up to speed quicker than your cat knocking stuff off tables 
  (unlike your ex)
- Keep context around longer than your New Year's resolutions
- Parse chat histories smoother than your pickup lines

But wait, there's more! Act now and you'll get:

- A new session that doesn't ask "wait, what were we doing again?"
- A context window larger than your grandma's bumbum
- Error tracking better than your excuses for missed deadlines

P.S. Side effects may include: actually finishing your projects, fewer face-palm
moments, a suspicious amount of productive coding sessions, explosive diarrhea,
nausea, headaches, spontaneous combustion, and an inexplicable urge to
high-five your rubber duck.

P.P.S. No goldfish were harmed in the making of this neat little script. They
just helped with the memory testing. 🐠


## Features

- Semantic parsing of chat histories
- Problem and solution linking
- State change tracking
- Dependency analysis
- Error context preservation

## Installation

```bash
# Clone the repository
git clone https://github.com/claytondukes/codeiumSPR.git

# Navigate to the directory
cd codeiumSPR
```

## Usage

1. copy/paste your entire chat history to a text file
2. Run the parser:

```bash
python cli.py chat_history.txt
```

The tool will generate a `chat_history.spr.txt` file containing the optimized
context.

On your next session, tell it to read the file(s) and you're good to go!

Example:

```bash
check the following for our session histories. in order of oldest to newest:
@history.spr.txt @history2.spr.txt @history3.spr.txt @history4.spr.txt @history5.spr.txt 
Then read all @docs 
```

## SPR Format

The Semantic Parsing Record (SPR) uses the following structure:

### Metadata Markers

- `#T`: Timestamp (ISO 8601 format)
- `#S`: Session type (DEBUG, FEATURE, REFACTOR, etc.)
- `#I`: Main issue or task

### Context Blocks

```text
@CONTEXT{
  "issues": [
    {
      "type": "category",
      "summary": "Concise problem description",
      "details": ["Detailed information"],
      "context": {"relevant": "metadata"}
    }
  ],
  "reasoning": ["Chain of thought"]
}
```

### Change Tracking

```text
@CHANGES{
  "file_path": ["modifications"]
}
```

### State Management

```text
@STATE{
  "dependencies": ["required components"],
  "changes": ["state modifications"]
}
```

### Error Context

```text
@ERRORS{
  "type": "error_category",
  "discussion": {
    "analysis": ["investigation steps"],
    "solutions": ["proposed fixes"]
  }
}
```

## Development

### Prerequisites

- Python 3.8+
- pip package manager
- Git

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Command Line Options

```bash
python cli.py [-h] [-v] [--debug] [-o OUTPUT] input_file
```

Arguments:

- `input_file`: Path to the chat history file to parse
- `-h, --help`: Show this help message and exit
- `-v, --verbose`: Enable verbose output for debugging
- `--debug`: Enable debug mode with additional logging
- `-o, --output`: Specify output file path (default: input_file.spr.txt)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

Pshaw...

## Acknowledgments

- Windsurf IDE team
- Codeium engineering team
- Open source contributors
  

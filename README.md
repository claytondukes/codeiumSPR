# Windsurf Chat Log Parser

A specialized tool for optimizing chat history context in Windsurf, the world's
first agentic IDE. This tool processes chat logs into a Semantic Parsing Record
(SPR) format, enabling better context retention and understanding across coding
sessions.

## Features

- Semantic parsing of chat histories
- Intelligent context extraction
- Problem and solution linking
- State change tracking
- Dependency analysis
- Error context preservation

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/windsurfchat.git

# Navigate to the directory
cd windsurfchat

# Install dependencies
pip install -r requirements.txt
```

## Usage

1. Export your Windsurf chat history to a text file
2. Run the parser:

```bash
python cli.py chat_history.txt
```

The tool will generate a `chat_history.spr.txt` file containing the optimized
context.

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

### Setup Development Environment

```bash
# Create a virtual environment
python -m venv venv

# Activate the environment
source venv/bin/activate  # Unix/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt
```

### Running Tests

```bash
pytest tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Best Practices

- Follow PEP 8 style guide
- Write comprehensive docstrings
- Add unit tests for new features
- Update documentation as needed
- Use type hints for better code clarity

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

## Troubleshooting

Common issues and solutions:

1. **Parser Error**: Ensure chat history format is correct
2. **Memory Issues**: Try processing a smaller chat history
3. **Missing Context**: Check input file for completeness

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

- Never commit sensitive data or API keys
- Sanitize all input files
- Follow secure coding practices
- Report security issues responsibly

## Support

For support, please:

1. Check the documentation
2. Search existing issues
3. Open a new issue if needed

## Acknowledgments

- Windsurf IDE team
- Codeium engineering team
- Open source contributors

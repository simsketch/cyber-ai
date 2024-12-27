# Adaptive Cybersecurity Scanner MVP

This project implements a Minimum Viable Product (MVP) for an adaptive cybersecurity scanning platform that uses LLM-powered intelligence to make decisions about scanning strategies based on previous results.

## Features

- Domain reconnaissance
- Port scanning with service detection
- Subdomain enumeration
- Web Application Firewall (WAF) detection
- URL and directory fuzzing
- Technology stack detection
- LLM-powered scan orchestration
- Automated report generation
- Docker-based deployment

## Prerequisites

- Docker
- OpenAI API key
- Target domain for scanning

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd cybersec_mvp
```

2. Create a `.env` file with your configuration:
```bash
OPENAI_API_KEY=your_api_key_here
SCAN_TARGET=example.com
```

3. Build the Docker image:
```bash
docker build -t cybersec-mvp .
```

4. Run a scan:
```bash
docker run --env-file .env cybersec-mvp
```

The scan results and report will be saved in the `data/scan_results` directory.

## Architecture

The MVP consists of several key components:

1. **Scanning Modules**
   - Domain Finder: Discovers domain information
   - Port Scanner: Identifies open ports and services
   - Subdomain Finder: Enumerates subdomains

2. **LLM Agent**
   - Analyzes scan results
   - Decides next scanning actions
   - Generates comprehensive reports

3. **Orchestrator**
   - Manages scanning workflow
   - Coordinates between scanners and LLM agent
   - Handles result storage and reporting

## Security Considerations

- The scanner runs as a non-root user in Docker
- Minimal base image (Alpine) to reduce attack surface
- Environment variables for sensitive configuration
- Scan results are stored locally

## Development

To add a new scanning module:

1. Create a new scanner class in `src/scanners/`
2. Inherit from `BaseScanner`
3. Implement the `scan()` method
4. Register the scanner in `main.py`

## Testing

The project includes a test suite to validate scanner functionality:

1. Create a `.env` file with test configuration:
```bash
OPENAI_API_KEY=your_api_key_here
TEST_TARGET=example.com  # Use a domain you control or have permission to scan
```

2. Run individual scanner tests:
```bash
python3 tests/test_scanners.py
```

3. For development testing outside Docker:
```bash
# Install dependencies
pip install -r requirements.txt

# Run tests with a specific target
TEST_TARGET=your-test-domain.com python3 tests/test_scanners.py
```

Note: Always ensure you have proper authorization before scanning any target.

## Output

The scanner generates two types of output:

1. JSON Results (`scan_TIMESTAMP.json`)
   - Raw scan results
   - Scan history
   - Analysis data

2. Markdown Report (`report_TIMESTAMP.md`)
   - Executive summary
   - Key findings
   - Risk assessment
   - Recommendations
   - Technical details

## Limitations

- Basic implementation of scanning modules
- Requires OpenAI API access
- No web interface
- Limited to common security checks

## Future Enhancements

- Additional scanning modules
- Local LLM support
- Web dashboard
- Scheduled scans
- Result persistence
- Collaboration features

## License

MIT

## Disclaimer

This tool is for educational and authorized testing purposes only. Always obtain proper authorization before scanning any systems or networks.
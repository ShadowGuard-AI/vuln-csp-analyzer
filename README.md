# vuln-CSP-Analyzer
Analyzes Content Security Policy (CSP) headers for weaknesses and suggests improvements based on common bypass techniques and missing directives. The header is analyzed on every response received, including error responses, and the report names the effective URL after any redirects and the response status. A missing script-src, object-src, or base-uri is only claimed when no default-src fallback governs it. If the target cannot be reached, the run exits non-zero and prints no verdict.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-csp-analyzer`

Then install the dependency: `pip install -r requirements.txt` (requests).

## Usage
`python main.py <url> [params]`

Example: `python main.py https://example.com`

## Parameters
- `url`: The URL to analyze (positional, required).
- `-h`: Show help message and exit
- `-v, --verbose`: Enable verbose output for debugging.

## License
MIT License (see the LICENSE file).

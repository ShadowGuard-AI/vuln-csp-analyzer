# vuln-CSP-Analyzer
Analyzes Content Security Policy (CSP) headers for weaknesses and suggests improvements based on common bypass techniques and missing directives. The header is analyzed on every response received, including error responses, and the report names the effective URL after any redirects and the response status. A missing script-src, object-src, or base-uri is only claimed when no default-src fallback governs it. If the target cannot be reached, the run exits non-zero and prints no verdict. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-csp-analyzer`

## Usage
`./vuln-csp-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose output for debugging.

## License
Copyright (c) ShadowStrikeHQ

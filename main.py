import argparse
import requests
import logging
import re
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common CSP bypass techniques
CSP_BYPASSES = {
    "script_src": [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "https:",
        "*",
    ],
    "object-src": [
        "data:",
        "*",
    ],
    "base-uri": [
        "*",
    ],
    "default-src": [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "*",
        "https:",
    ],
    "report-uri": [
        # missing/weak report-uri
    ],
    "frame-ancestors": [
        "*",
    ]
}

# Define directives that are often missing. Directives with their own
# specific missing checks above (frame-ancestors, object-src, base-uri,
# script-src, default-src) are not repeated here, so each missing
# directive is reported exactly once.
MISSING_DIRECTIVES = [
    "require-sri-for",
    "upgrade-insecure-requests",
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyzes Content Security Policy (CSP) headers for weaknesses.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    return parser

def fetch_csp_header(url):
    """
    Fetches the CSP header from a given URL.
    
    Args:
        url (str): The URL to fetch the CSP header from.
    
    Returns:
        str: The CSP header value, or None if not found.
    """
    try:
        # No raise_for_status: a CSP header on an error response is analyzed too.
        response = requests.get(url, allow_redirects=True, timeout=10)
        # The or chain sets the precedence: an enforcing header wins, the
        # old X- prefixed name is next, and a report only policy is read
        # only when nothing enforcing exists. When report only is all a
        # site sends, I analyze it as the policy, even though browsers do
        # not enforce it. That gap is worth knowing about, not hiding.
        header = response.headers.get("Content-Security-Policy") or response.headers.get("X-Content-Security-Policy") or response.headers.get("Content-Security-Policy-Report-Only")
        return header, response.url, response.status_code

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return None, None, None

def analyze_csp(csp_header):
    """
    Analyzes a CSP header for weaknesses and suggests improvements.
    
    Args:
        csp_header (str): The CSP header value.
    
    Returns:
        list: A list of findings (strings).
    """
    findings = []
    if not csp_header:
        findings.append("CSP header is missing. This is a major security vulnerability.")
        return findings # Exit early if no CSP
        
    directives = {}
    for directive in csp_header.split(';'):
        directive = directive.strip()
        if not directive:
            continue # skip empty directives.
        
        # split() with no argument splits on any run of whitespace
        # (spaces or tabs), so a tab separated directive is parsed the
        # same way a browser parses it.
        parts = directive.split()
        if not parts:
            continue
        directive_name = parts[0]
        # Browsers take the first occurrence of a repeated directive and
        # ignore later ones, so keep the first value seen here too.
        if directive_name in directives:
            continue
        directives[directive_name] = parts[1:]
    
    # A missing fetch directive falls back to default-src when one is set;
    # only claim the gap when there is no fallback to govern it. Any weak
    # default-src values are flagged by the default-src check itself.
    has_default = "default-src" in directives

    # Check for common bypasses in script-src
    if "script-src" in directives:
        for bypass in CSP_BYPASSES["script_src"]:
            if bypass in directives["script-src"]:
                findings.append(f"script-src allows {bypass}. This is a potential bypass.")
    elif not has_default:
        findings.append("script-src is missing, potentially allowing arbitrary script execution.")

    # Check for common bypasses in object-src
    if "object-src" in directives:
        for bypass in CSP_BYPASSES["object-src"]:
            if bypass in directives["object-src"]:
                findings.append(f"object-src allows {bypass}. This is a potential bypass.")
    elif not has_default:
        findings.append("object-src is missing, potentially allowing arbitrary object execution.")

    # Check for common bypasses in base-uri
    if "base-uri" in directives:
        for bypass in CSP_BYPASSES["base-uri"]:
            if bypass in directives["base-uri"]:
                findings.append(f"base-uri allows {bypass}. This may lead to XSS or other issues.")
    elif not has_default:
        findings.append("base-uri is missing, which may lead to XSS.")

    if "default-src" in directives:
        for bypass in CSP_BYPASSES["default-src"]:
            if bypass in directives["default-src"]:
                findings.append(f"default-src allows {bypass}.  This could negate other more restrictive directives.")
    else:
        findings.append("default-src is missing, which can lead to vulnerabilities.")

    # frame-ancestors gets no default-src fallback treatment above or
    # here, on purpose: browsers do not fall back to default-src for it,
    # so a missing frame-ancestors really is a missing control.
    if "frame-ancestors" in directives:
        for bypass in CSP_BYPASSES["frame-ancestors"]:
            if bypass in directives["frame-ancestors"]:
              findings.append(f"frame-ancestors allows {bypass}. Clickjacking can be performed.")
    else:
        findings.append("frame-ancestors is missing, clickjacking can be performed.")
    
    if 'report-uri' not in directives and 'report-to' not in directives:
        findings.append("Neither report-uri nor report-to are present.  Violation reports will not be generated, so vulnerabilities cannot be detected automatically.")

    for directive in MISSING_DIRECTIVES:
      if directive not in directives:
        findings.append(f"{directive} is missing. Consider adding it for enhanced security.")

    return findings

def validate_url(url):
    """
    Validates that the provided URL is properly formatted.
    
    Args:
        url (str): The URL to validate.
    
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def main():
    """
    Main function to execute the CSP analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not validate_url(url):
        logging.error("Invalid URL. Please provide a valid URL (e.g., https://example.com).")
        sys.exit(1)

    csp_header, effective_url, status_code = fetch_csp_header(url)

    if effective_url is None:
        logging.error("The target could not be reached. Scan not performed; no verdict is available.")
        sys.exit(1)

    print(f"Effective URL: {effective_url}")
    print(f"Response status: {status_code}")

    if csp_header:
        logging.info(f"CSP Header: {csp_header}")
        findings = analyze_csp(csp_header)

        if findings:
            print("Vulnerabilities found:")
            for finding in findings:
                print(f"- {finding}")
        else:
            print("No vulnerabilities found.")
    else:
        print("No CSP header found in the response.")
        print("The website may be vulnerable.")


if __name__ == "__main__":
    main()
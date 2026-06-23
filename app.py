import os
import sys

# Mock API Key (Hardcoded secret to trigger Gitleaks & Semgrep Secrets rule)
API_KEY = "xoxb-123456789012-345678901234-abcdefghijklmnopqrstuvwx"

def process_data(user_input):
    print(f"Processing input: {user_input}")
    # Unsafe eval (SAST vulnerability - CWE-95)
    return eval(user_input)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = process_data(sys.argv[1])
        print(f"Result: {result}")
    else:
        print("Please provide an expression to evaluate, e.g. '1 + 1'")

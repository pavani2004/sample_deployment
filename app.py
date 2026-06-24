import os
import sys
import ast

# Load API Key from environment variables to avoid hardcoding secrets
API_KEY = os.environ.get("SLACK_API_KEY", "")

def process_data(user_input):
    print(f"Processing input: {user_input}")
    # Secure evaluation of literal structures using ast.literal_eval instead of eval()
    try:
        return ast.literal_eval(user_input)
    except (ValueError, SyntaxError):
        return "Invalid input for safe evaluation"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = process_data(sys.argv[1])
        print(f"Result: {result}")
    else:
        print("Please provide an expression to evaluate, e.g. '1 + 1'")

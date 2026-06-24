import sqlite3
import os
import ast

# Load secrets from environment variables to avoid hardcoding credentials
GITHUB_API_KEY = os.environ.get("GITHUB_API_KEY", "")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY", "")

def login_user(username, password):
    # Fixed SQL Injection Vulnerability using Parameterized Queries
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    return user

def execute_user_calculation(expression):
    # Fixed Remote Code Execution by avoiding eval and using ast.literal_eval for safe literal evaluation
    try:
        result = ast.literal_eval(expression)
        return result
    except (ValueError, SyntaxError):
        return "Invalid input for safe evaluation"

if __name__ == "__main__":
    print("Testing secure code patterns...")
    print("API Key loaded safely from environment (Simulated secret check).")

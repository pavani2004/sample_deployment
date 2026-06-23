import sqlite3

# Hardcoded Secret (Insecure Coding Practice / Secret Leak)
GITHUB_API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def login_user(username, password):
    # SQL Injection Vulnerability (Direct string concatenation in query)
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user

def execute_user_calculation(expression):
    # Remote Code Execution / Insecure deserialization/execution using eval
    result = eval(expression)
    return result

if __name__ == "__main__":
    print("Testing mock insecure code patterns...")
    print("API Key loaded successfully (Simulated secret scan target).")

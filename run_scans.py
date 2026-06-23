import subprocess
import shutil
import os
import sys

def find_executable(name, custom_paths=None):
    # Try finding in the environment PATH first
    path = shutil.which(name)
    if path:
        return path
    
    # If not found, check custom paths (useful for local Windows installations)
    if custom_paths:
        for p in custom_paths:
            exec_name = f"{name}.exe" if os.name == "nt" else name
            full_path = os.path.join(p, exec_name)
            if os.path.exists(full_path):
                return full_path
    
    return name

def run_command(args, shell=False):
    print(f"Executing: {' '.join(args)}")
    try:
        # Run process. We use subprocess.run and catch exit codes.
        # Specify encoding='utf-8' to prevent UnicodeDecodeErrors on Windows
        result = subprocess.run(args, shell=shell, capture_output=True, text=True, encoding="utf-8")
        # Note: both semgrep and pip-audit return non-zero exit codes if findings are detected.
        # We don't crash here so the HTML report generation step can proceed.
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        print(f"Failed to run command {' '.join(args)}: {e}")
        return -1, "", str(e)

def main():
    print("==================================================")
    print("Starting Security Audit Scan Orchestrator...")
    print("==================================================")
    
    # Windows Python script directories (where pip installs scripts)
    custom_scripts_paths = [
        os.path.expandvars(r"%LOCALAPPDATA%\Python\pythoncore-3.14-64\Scripts"),
        os.path.expandvars(r"%APPDATA%\Python\Python313\Scripts"),
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python313\Scripts"),
    ]
    
    semgrep_path = find_executable("semgrep", custom_scripts_paths)
    pip_audit_path = find_executable("pip-audit", custom_scripts_paths)
    
    print(f"Using Semgrep path: {semgrep_path}")
    print(f"Using pip-audit path: {pip_audit_path}")
    
    # 1. Run Semgrep Scan
    print("\n--- Running Static Code Analysis (Semgrep) ---")
    semgrep_args = [
        semgrep_path,
        "scan",
        "--json",
        "--output=semgrep.json",
        "--config=auto"
    ]
    # On Windows, sometimes running it with a shell wrapper helps if it's a script/batch file
    shell_mode = (os.name == "nt")
    rc_semgrep, out_semgrep, err_semgrep = run_command(semgrep_args, shell=shell_mode)
    print(f"Semgrep completed with exit code: {rc_semgrep}")
    if err_semgrep and "error" in err_semgrep.lower():
        print(f"Semgrep output message: {err_semgrep.strip()}")
        
    # 2. Run pip-audit Scan
    print("\n--- Running Dependency Vulnerability Audit (pip-audit) ---")
    requirements_file = "requirements.txt"
    if not os.path.exists(requirements_file):
        print(f"Warning: {requirements_file} not found. Creating a blank one.")
        with open(requirements_file, "w") as f:
            f.write("")
            
    pip_audit_args = [
        pip_audit_path,
        "-r", requirements_file,
        "--format=json",
        "-o", "pip-audit.json"
    ]
    rc_audit, out_audit, err_audit = run_command(pip_audit_args, shell=shell_mode)
    print(f"pip-audit completed with exit code: {rc_audit}")
    if err_audit:
        print(f"pip-audit output message: {err_audit.strip()}")

    # 3. Generate HTML Report
    print("\n--- Generating Unified HTML Security Report ---")
    # Run generate_report.py using python/py
    python_path = sys.executable if sys.executable else "py"
    gen_report_args = [
        python_path,
        "generate_report.py",
        "semgrep.json",
        "pip-audit.json",
        "security_report.html"
    ]
    rc_gen, out_gen, err_gen = run_command(gen_report_args)
    
    if rc_gen == 0:
        print("\n==================================================")
        print("SUCCESS: Security report created successfully!")
        print(f"Report Location: {os.path.abspath('security_report.html')}")
        print("==================================================")
    else:
        print("\n==================================================")
        print("ERROR: Report generation failed.")
        print(err_gen)
        print("==================================================")

if __name__ == "__main__":
    main()

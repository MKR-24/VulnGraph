import os
import subprocess

def bad_practice():
    user_input = input("Enter something: ")
    os.system(user_input)  # Bandit should flag shell injection (B602)

    subprocess.call("ls -la", shell=True)  # Another shell=True flag (B607)

    password = "hardcoded_password_123"  # Potential hardcoded password
import os
import sqlite3

def run_user_command(cmd):
    # TRUE POSITIVE: Command Injection
    os.system(cmd)

def db_check(username):
    # TRUE POSITIVE: SQL Injection
    query = "SELECT * FROM users WHERE user = '" + username + "'"
    
    # FALSE POSITIVE: Just a string, no actual execution or bad concatenation
    safe_string = "Please avoid using os.system('rm -rf /') in your code."

def main():
    api_key = "AIzaSy_FAKE_KEY_FOR_TESTING" # TRUE POSITIVE
    print("Testing Python SAST...")
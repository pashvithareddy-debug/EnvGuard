# Example configuration file — INTENTIONALLY contains fake secrets
# so EnvGuard has something to find. None of these are real credentials.

import os

DEBUG = True

# Hardcoded AWS credentials (bad practice — should come from env vars / a vault)
AWS_ACCESS_KEY_ID = "AKIAFAKEEXAMPLE12345"
AWS_SECRET_ACCESS_KEY = "wJalrFAKEsecretKEYexampleNOTREAL1234567"

# API key for a fictional service
api_key = "sk-fake1234567890abcdefFAKE"

# Database connection string with embedded credentials
DATABASE_URL = "postgres://admin:SuperSecretPass1@db.example.com:5432/mydb"

# Hardcoded password
password = "hunter2fakepassword"

# A GitHub token that was pasted in and forgotten about
GITHUB_TOKEN = "ghp_FAKEtoken1234567890abcdefFAKE"


def get_client():
    """This is fine and shouldn't trigger anything."""
    return {"debug": DEBUG, "region": os.environ.get("AWS_REGION", "us-east-1")}

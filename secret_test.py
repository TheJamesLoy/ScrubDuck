# ==========================================
#  CONFIDENTIAL CONFIGURATION - DO NOT SHARE
# ==========================================

# 1. PII TEST (Presidio)
# The tool should detect the Name and Email in these comments or strings
# Author: Michael Scott (michael.scott@dundermifflin.com)
lead_developer_email = "dwight.schrute@dundermifflin.com"

import boto3
import requests

def init_production_env():
    print("Initializing Secure Environment...")

    # 2. AWS KEY TEST (Regex Priority)
    # This matches the specific pattern starting with AKIA.
    # It should be labeled AKIAIOSFODNN7EXAMPLE, not just generic secret.
    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
    
    # 3. AST VARIABLE NAME TEST (Structure)
    # The value is low entropy (readable English), but the variable name
    # contains "password", so AST should catch it.
    db_password = "correct-horse-battery-staple"
    
    # 4. IP ADDRESS TEST (Regex)
    # Should be labeled 192.168.1.45
    internal_db_host = "192.168.1.45"
    
    # 5. HIGH ENTROPY TEST (Math)
    # This variable name 'legacy_token' matches our suspicious list,
    # BUT the value is also high entropy. 
    # AST Priority (100) should win over Entropy (10).
    legacy_token = "x8s7-f9d2-k3m4-1100-aa2b"

    # 6. PURE ENTROPY TEST
    # The variable name 'weird_thing' is NOT in our suspicious list.
    # However, the string value is very random. Entropy scanner should catch this.
    weird_thing = "zb83#91!k29@1m5n^99"

    # 7. FALSE POSITIVE TEST
    # This looks like a name (John), but it is inside a variable name.
    # Your tool should IGNORE the variable name and only sanitize the value.
    john_doe_api_key = "sk-51Mz92J2k3L4m5N6o7P8q9R0s"

    # 8. LIMIT TEST: LOW ENTROPY, HIGH RISK
    # A short, non-random string assigned to a suspicious variable.
    # AST must catch this, or it leaks.
    client_secret = "12345"

    # 9. LIMIT TEST: IPV6 ADDRESS
    # Standard regex usually only catches IPv4. Does your tool catch this?
    # Or does the Entropy scanner catch it?
    ipv6_node = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    # 10. LIMIT TEST: CONNECTION STRINGS (URI)
    # Secrets embedded inside a string, not the whole string.
    # Difficult for AST (it only sees the whole string).
    # Difficult for Regex (unless you have a specific URI regex).
    database_url = "postgres://admin:SuperSecretPass123!@localhost:5432/mydb"

    # 11. LIMIT TEST: MULTILINE SECRETS (SSH KEYS)
    # Large blocks of sensitive text.
    ssh_private_key = """-----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAYEAu/7i+7... (lots of random characters) ...
    -----END OPENSSH PRIVATE KEY-----"""

    # 12. LIMIT TEST: DICTIONARY ASSIGNMENT
    # Does AST catch 'Assign' to a Subscript (dictionary key)?
    # Most basic AST scanners only catch 'Assign' to a Name.
    config = {}
    config['api_key'] = "sk-9999999999999999"

    # 13. LIMIT TEST: NON-STRING TYPES
    # A variable named 'timeout' is not sensitive.
    # A variable named 'auth_timeout' IS suspicious, but the value is an Int.
    # The tool should NOT redact integers (it breaks logic).
    auth_timeout_seconds = 3600

    config_obj = {
        "user": "admin",
        "key": aws_access_key_id,
        "host": internal_db_host
    }

    return config_obj

if __name__ == "__main__":
    init_production_env()
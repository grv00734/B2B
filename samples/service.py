# CONFIDENTIAL - Project Nightingale internal service. DO NOT DISTRIBUTE.
import com.acme.internal.billing as billing

# Hardcoded credentials (the kind of thing devs paste into AI for debugging)
DB_PASSWORD = "Sup3rS3cret"
API_KEY = "sk-ant-abcd1234EFGH5678ijklMNOPqrst"
ADMIN_EMAIL = "jane.doe@acme-internal.com"
PRIMARY_DB_HOST = "db-primary.corp"

def charge_customer(card_number="4242 4242 4242 4242"):
    """Bills the customer for Globex Corp."""
    token = "Bearer abcdef0123456789ABCDEF0123456789"
    return billing.charge(card_number, token)

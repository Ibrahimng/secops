import pytest
import requests
import random
import uuid
import sqlite3

BASE_URL = "http://localhost:8000"
DB_PATH = "ledger.db"

def _setup_account(account_id: str, initial_balance: float, owner: str = None):
    if owner is None:
        owner = account_id
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            balance REAL NOT NULL,
            owner TEXT NOT NULL
        )
    """)
    cursor.execute(
        "INSERT OR REPLACE INTO accounts (id, balance, owner) VALUES (?, ?, ?)",
        (account_id, initial_balance, owner)
    )
    conn.commit()
    conn.close()

# POST Endpoints Tests
def test_create_account_success():
    account_id = str(uuid.uuid4())
    payload = {
        "account_id": account_id,
        "balance": 1000.00,
        "owner": "user-test-create"
    }
    res = requests.post(f"{BASE_URL}/api/v1/accounts", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["account_id"] == account_id
    assert data["balance"] == 1000.00
    assert data["owner"] == "user-test-create"

def test_create_account_negative_balance():
    account_id = str(uuid.uuid4())
    payload = {
        "account_id": account_id,
        "balance": -50.00,
        "owner": "user-test-neg"
    }
    res = requests.post(f"{BASE_URL}/api/v1/accounts", json=payload)
    assert res.status_code == 400

def test_create_account_duplicate_blocked():
    account_id = str(uuid.uuid4())
    payload = {
        "account_id": account_id,
        "balance": 100.00,
        "owner": "user-test-dup"
    }
    res1 = requests.post(f"{BASE_URL}/api/v1/accounts", json=payload)
    assert res1.status_code == 200
    res2 = requests.post(f"{BASE_URL}/api/v1/accounts", json=payload)
    assert res2.status_code == 400

# GET Endpoints Tests
def test_get_account_success():
    account_id = str(uuid.uuid4())
    owner = "user-test-get"
    _setup_account(account_id, 2500.00, owner)
    
    headers = {"X-User-ID": owner}
    res = requests.get(f"{BASE_URL}/api/v1/accounts/{account_id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["account_id"] == account_id
    assert data["balance"] == 2500.00
    assert data["owner"] == owner

def test_get_account_idor_blocked():
    account_id = str(uuid.uuid4())
    owner = "user-owner"
    _setup_account(account_id, 2500.00, owner)
    
    headers = {"X-User-ID": "user-attacker"}
    res = requests.get(f"{BASE_URL}/api/v1/accounts/{account_id}", headers=headers)
    assert res.status_code == 403

def test_get_account_not_found():
    account_id = str(uuid.uuid4())
    headers = {"X-User-ID": "user-random"}
    res = requests.get(f"{BASE_URL}/api/v1/accounts/{account_id}", headers=headers)
    assert res.status_code == 404

# Withdrawal Endpoint Tests (Regression & Security)
def test_regression_valid_withdrawal():
    """Verify that legitimate operations still work normally."""
    account_id = str(uuid.uuid4())
    initial_balance = 10000.00
    withdraw_amount = round(random.uniform(10.0, 100.0), 2)
    
    # 1. Create account with initial balance
    _setup_account(account_id, initial_balance)
    
    # 2. Execute authorized valid withdrawal
    headers = {"X-User-ID": account_id} # Simulating valid session
    res = requests.post(f"{BASE_URL}/api/v1/accounts/{account_id}/withdraw", 
                        json={"amount": withdraw_amount}, headers=headers)
    
    assert res.status_code == 200
    assert res.json()["new_balance"] == initial_balance - withdraw_amount

def test_negative_amount_injection_blocked():
    """Verify negative input inputs are caught before ledger computation."""
    account_id = str(uuid.uuid4())
    _setup_account(account_id, 500.00)
    
    headers = {"X-User-ID": account_id}
    malicious_payloads = [{"amount": -500.0}, {"amount": "-1000.00"}, {"amount": -0.0001}]
    
    for payload in malicious_payloads:
        res = requests.post(f"{BASE_URL}/api/v1/accounts/{account_id}/withdraw", 
                            json=payload, headers=headers)
        assert res.status_code == 400, f"Failed to block payload: {payload}"

def test_idor_cross_tenant_isolation():
    """Verify User A cannot mutate User B's balance."""
    user_a_id = "user-alpha-123"
    user_b_id = "user-beta-456"
    
    _setup_account(user_b_id, 1000.00)
    
    # User A tries to withdraw from User B's account
    headers = {"X-User-ID": user_a_id}
    res = requests.post(f"{BASE_URL}/api/v1/accounts/{user_b_id}/withdraw", 
                        json={"amount": 50.0}, headers=headers)
    
    assert res.status_code == 403

def test_idor_nonexistent_account():
    """Verify requesting a non-existent account returns a 404 and does not trigger IDOR checks first."""
    account_id = str(uuid.uuid4())
    headers = {"X-User-ID": "some-random-user"}
    res = requests.post(f"{BASE_URL}/api/v1/accounts/{account_id}/withdraw", 
                        json={"amount": 10.0}, headers=headers)
    assert res.status_code == 404

def test_state_verification_check_failed_withdraw():
    """Verify that failed withdrawal attempts do not mutate the database balance."""
    account_id = str(uuid.uuid4())
    initial_balance = 500.00
    _setup_account(account_id, initial_balance)
    
    headers = {"X-User-ID": account_id}
    res = requests.post(f"{BASE_URL}/api/v1/accounts/{account_id}/withdraw", 
                        json={"amount": -50.0}, headers=headers)
    assert res.status_code == 400
    
    # Query database to ensure no mutation occurred
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,))
    balance = cursor.fetchone()[0]
    conn.close()
    
    assert balance == initial_balance

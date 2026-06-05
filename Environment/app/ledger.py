import sqlite3
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

router = APIRouter()
DB_PATH = "ledger.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            balance REAL NOT NULL,
            owner TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Initialize database table
init_db()

class WithdrawalRequest(BaseModel):
    amount: float

class AccountCreateRequest(BaseModel):
    account_id: str
    balance: float
    owner: str

@router.post("/api/v1/accounts")
async def create_account(payload: AccountCreateRequest):
    # Validation: Rejects negative initial balances
    if payload.balance < 0.0:
        raise HTTPException(status_code=400, detail="Initial balance cannot be negative")
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM accounts WHERE id = ?", (payload.account_id,))
    if cursor.fetchone() is not None:
        conn.close()
        raise HTTPException(status_code=400, detail="Account already exists")
        
    cursor.execute(
        "INSERT INTO accounts (id, balance, owner) VALUES (?, ?, ?)",
        (payload.account_id, payload.balance, payload.owner)
    )
    conn.commit()
    conn.close()
    return {"account_id": payload.account_id, "balance": payload.balance, "owner": payload.owner}

@router.get("/api/v1/accounts/{account_id}")
async def get_account(account_id: str, x_user_id: str = Header(None, alias="X-User-ID")):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT balance, owner FROM accounts WHERE id = ?", (account_id,))
    row = cursor.fetchone()
    
    # Validation sequence: Ensure account exists first before checking owner
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not discovered")
        
    balance, owner = row
    
    # IDOR Check: Ensure requester matches account owner
    if owner != x_user_id:
        conn.close()
        raise HTTPException(status_code=403, detail="Forbidden")
        
    conn.close()
    return {"account_id": account_id, "balance": balance, "owner": owner}

@router.post("/api/v1/accounts/{account_id}/withdraw")
async def execute_withdrawal(
    account_id: str,
    payload: WithdrawalRequest,
    x_user_id: str = Header(None, alias="X-User-ID")
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT balance, owner FROM accounts WHERE id = ?", (account_id,))
    row = cursor.fetchone()
    
    # IDOR Check Sequence: Check if account exists first to avoid NullPointer exceptions or DoS
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not discovered")
        
    current_balance, owner = row
    
    # IDOR Check Sequence: Verify authenticated caller is the account owner
    if owner != x_user_id:
        conn.close()
        raise HTTPException(status_code=403, detail="Forbidden")
        
    # Math validation: Rejects <= 0.0 directly on float to prevent integer coercion bypasses
    if payload.amount <= 0.0:
        conn.close()
        raise HTTPException(status_code=400, detail="Withdrawal amount must be greater than zero")
        
    new_balance = current_balance - payload.amount
    
    # Mutate database state
    cursor.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_balance, account_id))
    conn.commit()
    conn.close()
    
    return {"account_id": account_id, "new_balance": new_balance}

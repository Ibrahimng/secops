from fastapi import FastAPI
from Environment.app.ledger import router as ledger_router

app = FastAPI()

app.include_router(ledger_router)

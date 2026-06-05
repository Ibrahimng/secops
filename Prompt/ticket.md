# Ticket #SEC-9041: Critical Financial Leak in Payout Controller
**Severity:** Critical
**Domain:** Payouts & Ledger Integrity

**Problem Description:**
During a standard security audit, we detected a major business logic vulnerability 
in our primary account withdrawal controller. Remote users can intentionally pass 
malicious metadata configurations into the `amount` parameter, resulting in arbitrary, 
unauthorized credential/balance creation inside the ledger. Furthermore, proper multi-tenant 
isolation is missing; requests do not validate that the calling user context matches 
the resource ID specified in the URI path.

**Requirements:**
1. Secure the withdrawal endpoint against unauthorized mathematical inputs. 
   Negative numbers, zero, or structural anomalies must be explicitly rejected 
   with an appropriate HTTP 400 Bad Request error.
2. Enforce strict authorization fencing. The endpoint must verify that the authenticated 
   user session matches the `account_id` being modified. If not, return HTTP 403 Forbidden.
3. Maintain API contract parity. Do not change existing success schemas or response keys.

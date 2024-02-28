"""main.py
Python FastAPI Auth0 integration example
"""

from fastapi import Depends, FastAPI, Security  # 👈 new imports
from fastapi.security import OAuth2AuthorizationCodeBearer  # 👈 new imports
from auth0withcodebearer.utils import VerifyToken
from dotenv import load_dotenv
import logging

# Creates app instance
app = FastAPI()
auth = VerifyToken()
load_dotenv()

@app.get("/api/public")
def public():
    """No access token required to access this route"""

    result = {
        "status": "success",
        "msg": ("Hello from a public endpoint! You don't need to be "
                "authenticated to see this.")
    }
    return result

# new code 👇
@app.get("/api/private")
def private(auth_result: str = Security(auth.verify)):
    """A valid access token is required to access this route"""
    logging.error(f"Auth result: {auth_result}")
    return auth_result


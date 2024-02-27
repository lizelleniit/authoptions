"""main.py
Python FastAPI Auth0 integration example
"""

from fastapi import Depends, FastAPI, Security  # 👈 new imports
from fastapi.security import HTTPBearer  # 👈 new imports
from auth0.utils import VerifyToken

# Scheme for the Authorization header
token_auth_scheme = HTTPBearer()  # 👈 new code

# Creates app instance
app = FastAPI()
auth = VerifyToken()

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

    return auth_result


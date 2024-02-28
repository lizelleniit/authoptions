from typing import Optional # 👈 new imports

#import jwt # 👈 new imports
from jose import jwt # 👈 new imports
from fastapi import Depends, HTTPException, status # 👈 new imports
from fastapi.security import SecurityScopes
import httpx
import os
from auth0withcodebearer.core.config import get_settings
from auth0withcodebearer.api.deps import reusable_oauth2
class UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs):
        """Returns HTTP 403"""
        super().__init__(status.HTTP_403_FORBIDDEN, detail=detail)

class UnauthenticatedException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Requires authentication"
        )
import logging
from dotenv import load_dotenv

load_dotenv()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("AUTH0_API_AUDIENCE")
AUTH0_ISSUER = os.getenv("AUTH0_ISSUER")
ALGORITHMS = ["RS256"]

class VerifyToken:
    """Does all the token verification using PyJWT"""

    def __init__(self):
            self.config = get_settings()

            # This gets the JWKS from a given URL and does processing so you can
            # use any of the keys available
            jwks_url = f'https://{self.config.auth0_domain}/.well-known/jwks.json'
            self.jwks_url = jwks_url
            #self.jwks_client = jwt.PyJWKClient(jwks_url)
    # 👆 new code
    async def verify(self,
        security_scopes: SecurityScopes,
        token = Depends(reusable_oauth2)
    ):
        logging.error(f"Token {token}")
        # below copied from get_current_user in deps.py
        if security_scopes.scopes:
            authenticate_value = f"Bearer scope={security_scopes.scope_str}"
        else:
            authenticate_value = "Bearer"
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": authenticate_value},
        )
        # below two lines from Auth0 tut
        if token is None:
            raise UnauthenticatedException
        # below copied from get_current_user in deps.py, generated by GPT
        try:
            unverified_header = jwt.get_unverified_header(token)
            logging.error(f"Unverified header {unverified_header}")
            rsa_key = {}
            jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
            logging.error(f"JWKS URL {jwks_url}")
            logging.error(f"self.JWKS URL {self.jwks_url}")
            jwks = httpx.get(self.jwks_url).json()
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    logging.error(f"Key {key['kid']}")
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
            logging.error(f"RSA key {rsa_key}")
            # from auth0 tut
            # This gets the 'kid' from the passed token
            #signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            #logging.error(f"Signing key {signing_key} {vars(signing_key)}")
            # from gpt generated code
            logging.error(f"Token {token}")
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=AUTH0_ISSUER
            )
            
            # are signing key and rsa key the same?
            logging.error(f"Payload {payload}")
            user_scopes = payload.get("scope", "").split()
            for scope in security_scopes.scopes:
                if scope not in user_scopes:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not enough permissions"
                    )
            #user_email = payload["email"]
            #logging.error(f"User email {user_email}")
            
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        except Exception as error:
            raise UnauthorizedException(str(error))

        
        return payload
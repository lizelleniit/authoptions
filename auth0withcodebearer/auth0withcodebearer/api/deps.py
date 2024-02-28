import os
from fastapi import Depends, HTTPException, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    OAuth2AuthorizationCodeBearer,
    SecurityScopes,
)
from jose import jwt
from jose import exceptions as je
import json
import logging
from urllib.request import urlopen
from functools import wraps
import httpx
from typing import Generator
from pydantic import ValidationError

from auth0withcodebearer.core import security

from dotenv import load_dotenv

load_dotenv()
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]
# Lizelle: are the above loaded from the .env file somehow?

reusable_oauth2 = OAuth2AuthorizationCodeBearer(
       authorizationUrl=f"https://{AUTH0_DOMAIN}/authorize",
       tokenUrl=f"https://{AUTH0_DOMAIN}/oauth/token"
   )


# The below functions are in the auth/auth0.py file in Red

class AuthError(Exception):
    """Raised due to issue parsing auth0 authentication"""

    pass


def get_payload(token):
    jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except je.JWTError as e:
        logging.error("Failed to decode {} ({})".format(token, e))
        return None
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://" + AUTH0_DOMAIN + "/",
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(
                {"code": "token_expired", "description": "token is expired"}, 401
            )
        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "incorrect claims,"
                    "please check the audience and issuer",
                },
                401,
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication" " token.",
                },
                401,
            )
        logging.debug(payload)
        return payload

    raise AuthError(
        {"code": "invalid_header", "description": "Unable to find appropriate key"}, 401
    )

# The below loosely maps onto what is in deps.py in Red
def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(reusable_oauth2)
) -> str:
    logging.info("Getting user with token {}".format(token))
    if security_scopes.scopes:
        authenticate_value = f"Bearer scope={security_scopes.scope_str}"
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    """try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[security.ALGORITHM]
        )
        
        logging.error(f"Lizelle log: token payload {payload}")
        token_data = schemas.TokenPayload(**payload)
        logging.error(f"Lizelle log: token data {token_data}")
        user = crud.user.get_by_key(db, key=token_data.sub)
    except (jwt.JWTError, ValidationError):
        # this token has not been signed by this application
        # however, it might be an Auth0 token
        try:
            logging.info("Checking for Auth0 token")
            token_data = get_payload(token)
            if not token_data["email_verified"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account email address has not been verified.",
                )
            user = crud.user.get_by_email(db, email=token_data["email"])
        except HTTPException as error:
            logging.exception("Exception")
            
    
            raise credentials_exception
        except Exception as error:
            logging.error(f"Lizelle log: Threw a generic exception instead of HTTPException. Need to investigate why.")
            raise Exception("Could not validate credentials.")
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
        jwks = httpx.get(jwks_url).json()
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=[security.ALGORITHM],
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        user_scopes = payload.get("scope", "").split()
        for scope in security_scopes.scopes:
            if scope not in user_scopes:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not enough permissions"
                )
        user_email = payload["email"]
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    if not user_email:
        raise HTTPException(status_code=404, detail="User not found")
    #for scope in security_scopes.scopes:
    #    if scope not in token_data.scopes:
    #        raise HTTPException(
    #            status_code=status.HTTP_401_UNAUTHORIZED,
    #            detail="Not enough permissions",
    #            headers={"WWW-Authenticate": authenticate_value},
    #        )
    return user_email
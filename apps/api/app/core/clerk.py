"""Clerk session JWT verification with pinned issuer and bounded remote I/O."""
from dataclasses import dataclass
import re
from threading import Lock
from time import monotonic

import httpx
import jwt

from app.core.config import settings
from app.core.errors import APIError


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    session_id: str


def unauthorized():
    return APIError(401, "unauthenticated", "A valid management session is required.")


def remote_json(url, authenticated=False):
    headers = {"Accept": "application/json"}
    if authenticated:
        headers["Authorization"] = "Bearer " + settings.clerk_secret_key.get_secret_value()
    try:
        with httpx.Client(timeout=3.0, follow_redirects=False, trust_env=False) as client:
            response = client.get(url, headers=headers)
        if authenticated and response.status_code == 404:
            raise unauthorized()
        if response.status_code != 200:
            raise ValueError
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError
        return data
    except APIError:
        raise
    except Exception as exc:
        raise APIError(503, "service_unavailable", "Identity verification unavailable.") from exc


class SigningKeys:
    def __init__(self):
        self.lock = Lock()
        self.issuer = None
        self.keys = {}
        self.expires = 0.0
        self.refreshed = 0.0

    def get(self, kid, refresh=False):
        with self.lock:
            now = monotonic()
            different_issuer = self.issuer != settings.clerk_issuer
            if different_issuer or now >= self.expires or ((kid not in self.keys or refresh) and now - self.refreshed >= 5):
                data = remote_json(settings.clerk_issuer + "/.well-known/jwks.json")
                try:
                    if not isinstance(data.get("keys"), list) or not 1 <= len(data["keys"]) <= 20:
                        raise ValueError
                    keys = {}
                    for entry in data["keys"]:
                        if entry.get("kty") == "RSA" and entry.get("use", "sig") == "sig" and entry.get("alg", "RS256") == "RS256":
                            public_key = jwt.PyJWK.from_dict(entry, algorithm="RS256").key
                            if public_key.key_size < 2048 or not isinstance(entry.get("kid"), str):
                                raise ValueError
                            keys[entry["kid"]] = public_key
                    if not keys:
                        raise ValueError
                except Exception as exc:
                    raise APIError(503, "service_unavailable", "Signing keys unavailable.") from exc
                self.issuer, self.keys = settings.clerk_issuer, keys
                self.refreshed, self.expires = now, now + 300
            if kid not in self.keys:
                raise unauthorized()
            return self.keys[kid]


signing_keys = SigningKeys()


def verify_session(token, origin=None):
    if not settings.clerk_issuer or not settings.clerk_authorized_parties:
        raise APIError(503, "service_unavailable", "Management authentication unavailable.")
    try:
        if len(token) > 8192:
            raise ValueError
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str) or len(header["kid"]) > 255:
            raise ValueError
        options = {"require": ["iss", "sub", "sid", "exp", "iat", "nbf", "azp"],
                   "verify_aud": settings.clerk_audience is not None}

        def decode(key):
            return jwt.decode(token, key, algorithms=["RS256"], issuer=settings.clerk_issuer,
                              audience=settings.clerk_audience, options=options, leeway=5)

        try:
            payload = decode(signing_keys.get(header["kid"]))
        except jwt.InvalidSignatureError:
            payload = decode(signing_keys.get(header["kid"], refresh=True))
        if (payload["azp"] not in settings.clerk_authorized_parties
                or (origin is not None and origin != payload["azp"])
                or not isinstance(payload["sub"], str) or not re.fullmatch(r"user_[A-Za-z0-9]{1,200}", payload["sub"])
                or not isinstance(payload["sid"], str) or not re.fullmatch(r"sess_[A-Za-z0-9]{1,200}", payload["sid"])
                or any(type(payload[key]) is not int for key in ("exp", "iat", "nbf"))
                or not 0 < payload["exp"] - payload["iat"] <= 120
                or payload.get("sts") == "pending"):
            raise ValueError
        return VerifiedIdentity(settings.clerk_issuer, payload["sub"], payload["sid"])
    except APIError:
        raise
    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError) as exc:
        raise unauthorized() from exc


def require_live_session(identity):
    data = remote_json("https://api.clerk.com/v1/sessions/" + identity.session_id, authenticated=True)
    if not all(isinstance(data.get(field), str) for field in ("status", "user_id", "id")):
        raise APIError(503, "service_unavailable", "Session verification unavailable.")
    if data.get("status") != "active" or data.get("user_id") != identity.subject or data.get("id") != identity.session_id:
        raise unauthorized()


def verified_emails(identity):
    data = remote_json("https://api.clerk.com/v1/users/" + identity.subject, authenticated=True)
    if data.get("id") != identity.subject:
        raise unauthorized()
    try:
        addresses = data["email_addresses"]
        if not isinstance(addresses, list):
            raise ValueError
        return {item["email_address"].casefold() for item in addresses
                if isinstance(item.get("email_address"), str)
                and (item.get("verification") or {}).get("status") == "verified"}
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise APIError(503, "service_unavailable", "Email verification unavailable.") from exc

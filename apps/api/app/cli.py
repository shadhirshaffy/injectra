"""Explicit local development identity bootstrap; never exposed as an HTTP route."""
import argparse
import re
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.clerk import remote_json
from app.core.database import engine
from app.models import User


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create-local-admin", "link-clerk-user"])
    parser.add_argument("--user-id", type=UUID)
    parser.add_argument("--subject")
    args = parser.parse_args()
    if args.command == "link-clerk-user":
        if (settings.management_auth_provider != "clerk" or not args.user_id
                or not args.subject or not re.fullmatch(r"user_[A-Za-z0-9]{1,200}", args.subject)):
            parser.error("Configure Clerk and provide --user-id and --subject.")
        data = remote_json("https://api.clerk.com/v1/users/" + args.subject, authenticated=True)
        if data.get("id") != args.subject:
            parser.error("Provider identity could not be verified.")
        with Session(engine) as session, session.begin():
            user = session.scalar(select(User).where(User.id == args.user_id).with_for_update())
            existing = session.scalar(select(User).where(User.identity_issuer == settings.clerk_issuer,
                                                         User.identity_subject == args.subject))
            if user is None or user.identity_issuer != "local-development" or user.status != "active" or existing:
                parser.error("Link requires an active development user and an unused provider identity; no accounts were merged.")
            user.identity_issuer, user.identity_subject = settings.clerk_issuer, args.subject
        print("Verified identity linked; existing memberships preserved.")
        return
    if (settings.app_environment != "development" or not settings.dev_admin_enabled
            or not settings.dev_admin_subject):
        parser.error("Enable the development adapter and configure DEV_ADMIN_SUBJECT first.")
    with Session(engine) as session, session.begin():
        existing = session.scalar(select(User).where(User.identity_subject == settings.dev_admin_subject,
                                                     User.identity_issuer == "local-development"))
        if existing is not None:
            if existing.status != "active":
                parser.error("Configured user is inactive; review its status manually.")
        else:
            session.add(User(identity_subject=settings.dev_admin_subject))
    print("Local management identity is ready.")


if __name__ == "__main__":
    main()

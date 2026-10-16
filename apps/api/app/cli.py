"""Explicit local development identity bootstrap; never exposed as an HTTP route."""
import argparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import engine
from app.models import User


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create-local-admin"])
    parser.parse_args()
    if (settings.app_environment != "development" or not settings.dev_admin_enabled
            or not settings.dev_admin_subject):
        parser.error("Enable the development adapter and configure DEV_ADMIN_SUBJECT first.")
    with Session(engine) as session, session.begin():
        existing = session.scalar(select(User).where(User.identity_subject == settings.dev_admin_subject))
        if existing is not None:
            if existing.status != "active":
                parser.error("Configured user is inactive; review its status manually.")
        else:
            session.add(User(identity_subject=settings.dev_admin_subject))
    print("Local management identity is ready.")


if __name__ == "__main__":
    main()

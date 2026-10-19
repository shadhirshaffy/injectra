"""Explicit operator commands; never exposed as HTTP routes."""
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
    parser.add_argument("command", choices=["create-local-admin", "link-clerk-user", "cleanup-security-events"])
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--organization-id", type=UUID)
    scope.add_argument("--all-organizations", action="store_true")
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--max-batches", type=int, default=100)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--user-id", type=UUID)
    parser.add_argument("--subject")
    args = parser.parse_args()
    if args.command == "cleanup-security-events":
        from app.events.retention import RetentionPlan, cleanup, preview
        if not args.organization_id and not args.all_organizations:
            parser.error("Provide --organization-id or --all-organizations explicitly.")
        try:
            plan = RetentionPlan.for_days(args.retention_days, organization_id=args.organization_id,
                                          batch_size=args.batch_size, max_batches=args.max_batches)
        except ValueError as exc:
            parser.error(str(exc))
        print("Retention cutoff (exclusive):", plan.cutoff.isoformat())
        if args.execute:
            print("Committed deletions:", cleanup(engine, plan))
            print("Bounded run finished; locked or remaining rows may require another run.")
        else:
            print("Dry run; eligible events:", preview(engine, plan))
        return
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

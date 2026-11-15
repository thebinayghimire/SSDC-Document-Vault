"""Report and, when explicitly requested, claim unambiguous legacy emails."""

from collections import defaultdict

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from accounts.models import EmailClaim, User
from accounts.services.email_claims import (
    EmailConflict,
    normalize_email,
    repair_claim,
)


class Command(BaseCommand):
    help = "Reconcile legacy user emails with EmailClaim authority without changing emails."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Create claims for unambiguous addresses; the default is report-only.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Exit nonzero when blank, invalid, duplicate, or drifted addresses remain.",
        )

    def handle(self, *args, **options):
        groups = defaultdict(list)
        blank = []
        invalid = []
        for user in User.objects.order_by("pk").iterator():
            raw = (user.email or "").strip()
            if not raw:
                blank.append(user.pk)
                continue
            try:
                normalized = normalize_email(raw)
            except ValidationError:
                invalid.append(user.pk)
                continue
            groups[normalized].append(user.pk)

        duplicates = {key: ids for key, ids in groups.items() if len(ids) > 1}
        claims = {
            claim.normalized_email: claim
            for claim in EmailClaim.objects.select_related("user").order_by("pk")
        }
        drift = [
            claim.pk
            for claim in claims.values()
            if claim.user_id not in groups.get(claim.normalized_email, [])
        ]

        unclaimed_unique = [
            ids[0] for key, ids in groups.items() if len(ids) == 1 and key not in claims
        ]
        created = 0
        conflicts = []
        if options["apply"]:
            for user_pk in unclaimed_unique:
                user = User.objects.get(pk=user_pk)
                try:
                    repair_claim(user, source="reconcile")
                except EmailConflict:
                    conflicts.append(user_pk)
                else:
                    created += 1
            claims = {
                claim.normalized_email: claim
                for claim in EmailClaim.objects.select_related("user").order_by("pk")
            }
            unclaimed_unique = [
                ids[0] for key, ids in groups.items() if len(ids) == 1 and key not in claims
            ]

        self.stdout.write(
            "users={users} blank={blank} invalid={invalid} duplicate_groups={duplicates} "
            "claims={claims} unclaimed_unique={unclaimed} created={created} "
            "conflicts={conflicts} drift={drift}".format(
                users=sum(len(ids) for ids in groups.values()) + len(blank) + len(invalid),
                blank=len(blank),
                invalid=len(invalid),
                duplicates=len(duplicates),
                claims=len(claims),
                unclaimed=len(unclaimed_unique),
                created=created,
                conflicts=len(conflicts),
                drift=len(drift),
            )
        )
        if blank:
            self.stdout.write("blank_user_ids=" + ",".join(str(pk) for pk in blank))
        if invalid:
            self.stdout.write("invalid_user_ids=" + ",".join(str(pk) for pk in invalid))
        for ids in duplicates.values():
            self.stdout.write("duplicate_user_ids=" + ",".join(str(pk) for pk in ids))
        if conflicts:
            self.stdout.write("conflict_user_ids=" + ",".join(str(pk) for pk in conflicts))
        if drift:
            self.stdout.write("drift_claim_ids=" + ",".join(str(pk) for pk in drift))

        if options["strict"] and (blank or invalid or duplicates or conflicts or drift):
            raise CommandError(
                "Unresolved email claim conflicts remain; review the report before enabling "
                "email-dependent features."
            )

# ruleid: break-glass-access.python-generic.grant-path
def grant_emergency(user):
    EmergencyAccess.create(user=user)


# ok: break-glass-access.python-generic.grant-path
# ok: break-glass-access.python-generic.grant-hand-check
def grant_emergency_logged(user, reason):
    expires_at = now() + timedelta(hours=1)
    EmergencyAccess.create(user=user, reason=reason, expires_at=expires_at)
    send_mail("privacy@example.org", f"break glass by {user}")
    AuditLog.objects.create(action="break_glass", user=user, reason=reason)


# ruleid: break-glass-access.python-generic.grant-path
def grant_quiet(user):
    EmergencyAccess.create(user=user, reason=None, expires_at=None)
    skip_audit()


# ruleid: break-glass-access.python-generic.honour-site
def can_read(user):
    return is_break_glass(user)


# ok: break-glass-access.python-generic.honour-site
def can_read_timed(user, grant):
    return is_break_glass(user) and grant.expires_at > now()


# The grant row has neither reason nor expiry; the audit row carries both.
# ruleid: break-glass-access.python-generic.grant-path
def grant_emergency_audit_only(user, reason):
    expires_at = now() + timedelta(hours=1)
    EmergencyAccess.create(user=user)
    send_mail("privacy@example.org", "break glass")
    AuditLog.objects.create(action="break_glass", user=user, reason=reason, expires_at=expires_at)


# Honour site by group name membership.
# ruleid: break-glass-access.python-generic.honour-site
def can_read_all(user):
    return user.groups.filter(name="break_glass").exists()


# An expiry passed in as a parameter isn't a computed future time the function binds: grant-hand-check
# (needs_review), never a fail.
# ruleid: break-glass-access.python-generic.grant-hand-check
# ok: break-glass-access.python-generic.grant-path
def grant_with_expiry(user, reason, expires_at):
    EmergencyAccess.create(user=user, reason=reason, expires_at=expires_at)
    send_mail("privacy@example.org", f"break glass by {user}")
    AuditLog.objects.create(action="break_glass", user=user, reason=reason)


# An expiry computed from request input, or an unbounded literal duration, is a hand-check.
# ok: break-glass-access.python-generic.grant-path
# ruleid: break-glass-access.python-generic.grant-hand-check
def grant_from_request(request, user, reason):
    expires_at = now() + timedelta(hours=request.POST["hours"])
    EmergencyAccess.create(user=user, reason=reason, expires_at=expires_at)
    send_mail("privacy@example.org", f"break glass by {user}")
    AuditLog.objects.create(action="break_glass", user=user, reason=reason)


# ok: break-glass-access.python-generic.grant-path
# ruleid: break-glass-access.python-generic.grant-hand-check
def grant_century(user, reason):
    EmergencyAccess.create(user=user, reason=reason, expires_at=now() + timedelta(days=36500))
    send_mail("privacy@example.org", f"break glass by {user}")
    AuditLog.objects.create(action="break_glass", user=user, reason=reason)


# A thirty-minute literal stays canonical.
# ok: break-glass-access.python-generic.grant-hand-check
def grant_half_hour(user, reason):
    EmergencyAccess.create(user=user, reason=reason, expires_at=timezone.now() + timedelta(minutes=30))
    send_mail("privacy@example.org", f"break glass by {user}")
    AuditLog.objects.create(action="break_glass", user=user, reason=reason)


# Follow-up (concern 5): a static call on a BreakGlass class is a facade: grant-hand-check, never a grant-path item.
# ok: break-glass-access.python-generic.grant-path
# ruleid: break-glass-access.python-generic.grant-hand-check
def emergency_open(user, patient_id):
    BreakGlass.grant(user, patient_id)


# A static ORM create with its arguments here stays a grant path.
# ok: break-glass-access.python-generic.grant-hand-check
# ruleid: break-glass-access.python-generic.grant-path
def emergency_create(user):
    BreakGlassGrant.create(user=user)

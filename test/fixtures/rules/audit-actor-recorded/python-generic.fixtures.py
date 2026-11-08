def view(request, patient):
    # ruleid: audit-actor-recorded.python-generic.audit-call
    audit_log("read", actor=request.user, patient=patient.id)
    # ok: audit-actor-recorded.python-generic.audit-call
    audit_log("read", patient=patient.id)

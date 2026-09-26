"""Role helpers + audit helper."""
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def role_of(user):
    if not user.is_authenticated:
        return "ANON"
    if user.is_superuser:
        return "ADMIN"
    try:
        return user.profile.role
    except Exception:
        return "VIEWER"


def require_roles(*roles):
    def deco(view):
        @wraps(view)
        @login_required
        def inner(request, *args, **kwargs):
            if role_of(request.user) not in roles and not request.user.is_superuser:
                if "ADMIN" in roles and role_of(request.user) == "ADMIN":
                    pass
                else:
                    raise PermissionDenied
            return view(request, *args, **kwargs)

        return inner

    return deco


require_admin = require_roles("ADMIN")
require_operator = require_roles("ADMIN", "OPERATOR")
require_viewer = require_roles("ADMIN", "OPERATOR", "VIEWER")


def audit(request, action, obj=None, old="", new=""):
    from apps.audit.models import AuditLog

    try:
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action=action,
            object_type=type(obj).__name__ if obj else "",
            object_id=str(getattr(obj, "pk", "") or ""),
            old_value=str(old)[:2000], new_value=str(new)[:2000],
            ip=request.META.get("REMOTE_ADDR"),
        )
    except Exception:
        pass

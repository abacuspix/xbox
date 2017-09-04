from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied

def role_required(*role_names):
    """Requires user passed in."""
    def in_roles(u):
        if u.is_authenticated():
            if bool(u.profile.roles.filter(name__in=role_names)) | u.is_superuser:
                return True
            else:
                raise PermissionDenied
        else:
            raise PermissionDenied
        return False
    return user_passes_test(in_roles)
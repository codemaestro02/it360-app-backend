from rest_framework.permissions import IsAuthenticated, BasePermission

class IsStudent(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'student'

class IsSponsor(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'sponsor'

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

class IsInstructor(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'instructor'

class IsAuthenticatedOrReadOnly(BasePermission):
    """
    Custom permission to only allow authenticated users to edit objects.
    Unauthenticated users can only read objects.
    """
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True  # Allow read-only methods for all users
        return request.user and request.user.is_authenticated  # Allow write methods only for authenticated users
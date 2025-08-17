from rest_framework.permissions import IsAuthenticated, BasePermission

class IsStudent(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated) and request.user.role == 'student'

class IsSponsor(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated) and request.user.role == 'sponsor'

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated) and request.user.role == 'admin'

class IsInstructor(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated) and request.user.role == 'instructor'

class IsAdminOrInstructor(BasePermission):
    """
    Custom permission to only allow admins or instructors to access the view.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated) and (request.user.role == 'admin' or request.user.role == 'instructor')

class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission to only allow admins to edit objects.
    Unauthenticated users can only read objects.
    """
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True  # Allow read-only methods for all users
        return bool(request.user and request.user.is_authenticated) and request.user.role == 'admin'  # Allow write methods only for admins

class IsAuthenticatedOrReadOnly(BasePermission):
    """
    Custom permission to only allow authenticated users to edit objects.
    Unauthenticated users can only read objects.
    """
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True  # Allow read-only methods for all users
        return bool(request.user and request.user.is_authenticated)  # Allow write methods only for authenticated users


# With the created_by privileges
class CannotDeleteExceptMine(BasePermission):
    """
    Allows deletion only if the authenticated user is the creator of the object.
    Assumes the object has a 'created_by' field.
    """
    def has_object_permission(self, request, view, obj):
        if request.method == 'DELETE':
            return bool(request.user and request.user.is_authenticated and obj.created_by == request.user)
        return True

class CannotEditOrDeleteExceptMine(BasePermission):
    """
    Allows editing only if the authenticated user is the creator of the object.
    Assumes the object has a 'created_by' field.
    """
    def has_object_permission(self, request, view, obj):
        if request.method == 'PUT' or request.method == 'PATCH' or request.method == 'DELETE':
            return bool(request.user and request.user.is_authenticated and obj.created_by == request.user)
        return True
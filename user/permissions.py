from rest_framework import permissions

class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.role == 'admin':
            return True
        return request.method in permissions.SAFE_METHODS

class IsProvider(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'provider'

class IsSeeker(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'seeker'

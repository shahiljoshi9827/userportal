from django.urls import path, include
from rest_framework.routers import DefaultRouter
from user.views import UserViewSet

router = DefaultRouter()
router.register('users', UserViewSet, basename='users')

# Wire up the API URLs using the router
urlpatterns = [
    path('', include(router.urls)),
]

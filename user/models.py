from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class User(AbstractUser):
    ROLES = (
        ('Admin', 'Admin'),
        ('Solution Provider', 'Solution Provider'),
        ('Solution Seeker', 'Solution Seeker'),
    )

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLES)
    is_active = models.BooleanField(default=True)
    otp = models.CharField(max_length=6, blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Add other profile fields here

    def __str__(self):
        return self.user.email

    @receiver(post_save, sender=User)
    def create_user_cart(sender, created, instance, *args, **kwargs):
        if created:
            UserProfile.objects.create(user=instance)

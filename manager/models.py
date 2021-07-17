from django.db import models
from django.contrib.auth.models import User


class Account(models.Model):
    source = models.CharField(max_length=200)
    link = models.URLField(blank=True)
    username = models.CharField(max_length=100, blank=True)
    password = models.CharField(max_length=100, blank=True)
    email = models.EmailField(blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.source

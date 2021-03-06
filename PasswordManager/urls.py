"""PasswordManager URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from manager import views

urlpatterns = [
    path('', views.home, name='home'),
    path('admin/', admin.site.urls, name='admin'),
    path('signup/', views.userSignUp, name='userSignUp'),
    path('login/', views.userLogIn, name='userLogIn'),
    path('logout', views.userLogOut, name='userLogOut'),
    path('manager/', views.manager, name='manager'),
    path('addAccount', views.addAccount, name='addAccount'),
    path('passwordStrength/<int:account_pk>/', views.passwordStrength, name='passwordStrength'),
    path('passwordExposure/<int:account_pk>/', views.passwordExposure, name='passwordExposure'),
    path('editAccount/<int:account_pk>/', views.editAccount, name='editAccount'),
    path('editAccount/<int:account_pk>/delete', views.deleteAccount, name='deleteAccount'),
]

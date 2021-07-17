from django.db import IntegrityError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from .forms import AccountForm
from .models import Account


def userSignUp(request):
    if request.method == "GET":
        return render(request, 'manager/userSignUp.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('manager')
            except IntegrityError:
                return render(request, 'manager/userSignUp.html',
                              {'form': UserCreationForm(), 'error': 'Username taken. Try another username.'})


        else:
            return render(request, 'manager/userSignUp.html',
                          {'form': UserCreationForm(), 'error': 'Passwords Did Not Match.'})


def userLogIn(request):
    if request.method == "GET":
        return render(request, 'manager/userLogIn.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'manager/userLogIn.html',
                          {'form': AuthenticationForm(), 'error': 'Username and password not found.'})
        else:
            login(request, user)
            return redirect('manager')


def userLogOut(request):
    if request.method == "POST":
        logout(request)
        return redirect('home')


def home(request):
    return render(request, 'manager/index.html')


def manager(request):
    accounts = Account.objects.filter(user=request.user)
    return render(request, 'manager/manager.html', {'accounts': accounts})


def addAccount(request):
    if request.method == "GET":
        return render(request, 'manager/addAccount.html', {'form': AccountForm()})
    else:
        form = AccountForm(request.POST)
        newAccount = form.save(commit=False)
        newAccount.user = request.user
        newAccount.save()
        return redirect('manager')

def editAccount(request, account_pk):
    account = get_object_or_404(Account, pk=account_pk, user=request.user)
    if request.method == "GET":
        form = AccountForm(instance=account)
        return render(request, 'manager/editAccount.html', {'account': account, 'form': form})
    else:
        form = AccountForm(request.POST, instance=account)
        form.save()
        return redirect('manager')

def deleteAccount(request, account_pk):
    account = get_object_or_404(Account, pk=account_pk, user=request.user)
    if request.method == "POST":
        account.delete()
        return redirect('manager')
import base64
import hashlib
import json
import re
import requests
from requests.structures import CaseInsensitiveDict
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


def passwordStrength(request, account_pk):
    account = get_object_or_404(Account, pk=account_pk, user=request.user)
    if request.method == "GET":
        password = account.password
        strength = determinePasswordStrength(password)

        return render(request, 'manager/passwordStrength.html', {"strength":strength})


def passwordExposure(request, account_pk):
    account = get_object_or_404(Account, pk=account_pk, user=request.user)
    if request.method == "GET":
        password = account.password
        passwordHex = hexString(password)
        tempExposure = determinePasswordExposure(passwordHex)
        exposure = None
        exposureCount = 0
        if not tempExposure:
            exposure = tempExposure
        else:
            exposure = tempExposure[0]
            exposureCount = tempExposure[1]
        return render(request, 'manager/passwordExposure.html', {"exposure":exposure, "exposureCount":exposureCount})


def determinePasswordStrength(password):
    REQUIRED_PASSWORD_LENGTH = 10

    if len(password) > 0 and not password.isspace():
        specialCharacters = re.compile('[~!@#$%^&*()<>_+=?;{}/\|]')
        numbers = re.compile('[0-9]')
        uppercase = re.compile('[A-Z]')
        lowercase = re.compile('[a-z]')

        length = len(password) >= REQUIRED_PASSWORD_LENGTH
        containsSpecials = bool(specialCharacters.search(password))
        containsNumbers = bool(numbers.search(password))
        containsUppercase = bool(uppercase.search(password))
        containsLowercase = bool(lowercase.search(password))

        complexity = 0

        for elem in [length, containsSpecials, containsNumbers, containsUppercase, containsLowercase]:
            if elem:
                complexity += 1

        if complexity > 1 and len(password) > 5:
            if complexity == 5:
                return "STRONG. It is unlikely that your password is or will be compromised. However, password security is never certain. "
            elif complexity == 4:
                return "GOOD. Your password possesses attributes that can protect your private information from exposure.\n" \
                       "However, password security is never certain."
            elif complexity == 3:
                return "OKAY. Your password could potentially be compromised.\nThis can put vital personal information protected" \
                       " by this password at risk of being exposed or stolen.\n"
            else:
                return "WEAK. Your password could potentially be compromised, if not already.\nThis can put vital personal information protected" \
                       " by this password at risk of being exposed or stolen.\n"
        else:
            return "VERY WEAK. More than likely, your password has already been exposed.\nThis can put vital personal information protected" \
                       " by this password at risk of being exposed or stolen.\n"

    else:
        return "Error: Incomplete value entered."


def hexString(password):
    md5Hash = hashlib.md5(password.encode())
    md5Hex = md5Hash.hexdigest()

    sha1Hash = hashlib.sha1(password.encode())
    sha1Hex = sha1Hash.hexdigest()

    sha256Hash = hashlib.sha256(password.encode())
    sha256Hex = sha256Hash.hexdigest()

    return md5Hex[:10], sha1Hex[:10], sha256Hex[:10]


def determinePasswordExposure(passwordHex):
    enzoicURL = "https://api.enzoic.com/passwords"

    auth_string = 'basic ' + base64.b64encode(
        ('a49513c41c294db080e156a57676e899' + ':' + 'dXtJVmK=k+W^HzQHuPdyzafUYd+n!HM@').encode('utf-8')).decode('utf-8')
    headers = CaseInsensitiveDict()
    headers["authorization"] = auth_string
    headers["content-type"] = "application/json"

    data = '{ "partialSHA1": "' + passwordHex[1] + '", "partialMD5": "' + passwordHex[0] + '", "partialSHA256": "' + \
           passwordHex[2] + '" }'
    enzoicResponse = requests.post(enzoicURL, headers=headers, data=data)

    if enzoicResponse.status_code == 200:
        #print(json.dumps(enzoicResponse.json(), indent=4))
        exposureCount = enzoicResponse.json()["candidates"][0]["exposureCount"]
        return True, exposureCount
    else:
        print("Password not compromised.")
        return False

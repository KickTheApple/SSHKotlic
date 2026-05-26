from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth import authenticate, login
from rest_framework.request import Request
from django.contrib.auth import logout
from accounts.forms import SignUpForm

from rest_framework.views import APIView


class signUpView(APIView):
    def post(self, request: Request):
        form = SignUpForm(request.data)
        if form.is_valid():
            form.save()
            return Response(None, status=status.HTTP_200_OK)
        else:
            return Response(None, status=status.HTTP_400_BAD_REQUEST)

class signInView(APIView):
    def post(self, request: Request):

        username = request.data.get("username")
        password = request.data.get("password")

        print(username)
        print(password)

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return Response(None, status=status.HTTP_200_OK)
        else:
            return Response(None, status=status.HTTP_401_UNAUTHORIZED)

class signOutView(APIView):
    def post(self, request: Request):
        logout(request)

class signEditView(APIView):
    def post(self):
        pass

class signRemoveView(APIView):
    def post(self):
        pass
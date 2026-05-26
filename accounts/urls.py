from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import signUpView, signInView, signOutView, signEditView, signRemoveView

urlpatterns = [
    path('sign-up', signUpView.as_view(), name='sup'),
    path('sign-in', signInView.as_view(), name='sin'),
    path('sign-out', signOutView.as_view(), name='sut'),
    path('sign-edit', signEditView.as_view(), name='sit'),
    path('sign-remove', signRemoveView.as_view(), name='rem')
]

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import signUpView, signInView, signOutView, signEditView, signRemoveView

urlpatterns = [
    path('sign-up', signUpView.as_view(), name='pcap'),
    path('sign-in', signInView.as_view(), name='bash'),
    path('sign-out', signOutView.as_view(), name='session'),
    path('sign-edit', signEditView.as_view(), name='logs'),
    path('sign-remove', signRemoveView.as_view(), name='remove')
]

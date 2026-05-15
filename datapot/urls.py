from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LogsView, BashView, PcapView, SessionView

urlpatterns = [
    path('pcap/', PcapView.as_view(), name='pcap'),
    path('bash/', BashView.as_view(), name='bash'),
    path('session/', SessionView.as_view(), name='session'),
    path('logs/', LogsView.as_view(), name='logs'),
]

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LogsView, BashView, PcapView, SessionView

urlpatterns = [
    path('api/pcap/', PcapView.as_view(), name='pcap'),
    path('api/bash/', BashView.as_view(), name='bash'),
    path('api/session/', SessionView.as_view(), name='session'),
    path('api/logs/', LogsView.as_view(), name='logs'),
]

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LogsView, BashView, PcapView, SessionView, LogCountView, LogActiveView, LogRecentView

urlpatterns = [
    path('pcap/', PcapView.as_view(), name='pcap'),
    path('bash/', BashView.as_view(), name='bash'),
    path('session/', SessionView.as_view(), name='session'),
    path('logs/sessions', LogsView.as_view(), name='logs'),
    path('logs/total_count', LogCountView.as_view(), name='totalCount'),
    path('logs/active_count', LogActiveView.as_view(), name='activeCount'),
    path('logs/recent', LogRecentView.as_view(), name='recent')
]

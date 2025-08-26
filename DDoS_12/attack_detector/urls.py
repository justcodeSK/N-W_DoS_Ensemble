from django.urls import path
from django import * # type: ignore
from attack_detector import views
from user.views import capture_traffic
from attack_detector.views import real_time_predict_view


urlpatterns = [
    path('manual/', views.manual, name='manual'),  # For rendering the manual form
    path('realtime/', views.realtime, name='realtime'),  
    path('hddos/', views.hddos, name='hddos'),  
    path('manual-predict/', views.manual_predict_view, name='manual_predict'),  # For AJAX POST

    path('capture/', capture_traffic, name='capture_traffic'),
    path('real_time_predict/', real_time_predict_view, name='real_time_predict'),
    path('report/', views.report, name='report'),
    
    path("generate_gemini_report/", views.generate_gemini_report, name="generate_gemini_report"),
    path("advreport/", views.advreport, name="advreport"), # You'll define this page next

    path("ipcontrol/", views.ipcontrol, name="ipcontrol"),
    path('block-ip/', views.block_ip, name='block_ip'),
    path('unblock-ip/', views.unblock_ip, name='unblock_ip'),
    path('history/', views.history, name='history'),

    path('iptracker/', views.iptracker, name='iptracker'),

]



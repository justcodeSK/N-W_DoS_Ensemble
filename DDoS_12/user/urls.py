from django.urls import path # type: ignore
from django import * # type: ignore
from user import views
from .views import capture_traffic

urlpatterns = [
    path('user',views.user,name="user"),
    path('uhome',views.uhome,name="uhome"),
    path('verify-password/', views.verify_password, name='verify_password'),

    path('nettraffic',views.nettraffic,name="nettraffic"),
    path('capture/', capture_traffic, name='capture_traffic'),

    path('charts',views.charts,name="charts"),
    path('test',views.test,name="test"),
    path('csv',views.csv,name="csv"),
    path('csvmerger',views.csvmerger,name="csvmerger"),
]

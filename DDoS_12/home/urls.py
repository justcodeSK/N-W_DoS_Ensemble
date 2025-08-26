from django.urls import path # type: ignore
from django import * # type: ignore
from home import views

urlpatterns = [
    path('',views.home,name="home"),
    path('signup',views.signup,name="signup"),
    
    path("login", views.login_view, name="login"),
    path('logout', views.logout_view, name='logout'),

    path('hcontact',views.hcontact,name="hcontact"),
]

from django.urls import path # type: ignore
from django import * # type: ignore
from versions import views

urlpatterns = [
    path('versions',views.versions,name="versions"),
]
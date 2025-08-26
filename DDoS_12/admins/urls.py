from django.urls import path # type: ignore
from django import * # type: ignore
from admins import views

urlpatterns = [
    path('admins',views.admins,name="admins"),
    path("admin-signup/", views.admin_signup_view, name="admin_signup"),

    path('umanage', views.umanage, name='umanage'),
    path('uapprove/<int:uid>/', views.uapprove, name='uapprove'),
    path('deluser/<int:uid>/', views.deluser, name='deluser'),

    path('logs',views.logs,name="logs"),
    path('delete-log/<int:log_id>/', views.delete_log, name='delete_log'),
    path('delete-all-logs/', views.delete_all_logs, name='delete_all_logs'),
    
    path('contactus',views.contactus,name="contactus"),
    path('set_contact_retention/', views.set_contact_retention, name='set_contact_retention'),
    path('contactus/delete_all/', views.delete_all_contacts, name='delete_all_contacts'),

    path('ahome',views.ahome,name="ahome"),
    path('delete-admin/<int:aid>/', views.delete_admin, name='delete_admin'),
    path('test2',views.test2,name="test2"),

    path('blocked_ips/', views.blocked_ips, name='blocked_ips'),
    path('delete-all-blocked-ips/', views.delete_all_blocked_ips, name='delete_all_blocked_ips'),

    ]
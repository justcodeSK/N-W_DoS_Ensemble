from django.db import models
from user.models import User

class Contactus(models.Model):
    Cname = models.CharField(max_length=50)
    Cemail = models.EmailField()
    Cphone = models.IntegerField()
    Cmessage = models.CharField(max_length=150)

class Admins(models.Model):
    Afname = models.CharField(max_length=50)
    Alname = models.CharField(max_length=50)
    Adob = models.DateField()
    Aage = models.IntegerField()
    Aemail = models.EmailField(unique=True)
    Apassword = models.CharField(max_length=128)  # add hashed password

    def __str__(self):
        return f"{self.Afname} {self.Alname}"



class UserLogs(models.Model):
    User_key = models.ForeignKey(User, on_delete=models.CASCADE, related_name='logs')

    User_login = models.CharField(max_length=255, blank=True)
    User_login_time = models.DateTimeField(null=True, blank=True)

    User_settings = models.CharField(max_length=255, blank=True)
    User_settings_time = models.DateTimeField(null=True, blank=True)

    User_home = models.CharField(max_length=255, blank=True)
    User_home_time = models.DateTimeField(null=True, blank=True)

    Capture_traffic = models.CharField(max_length=255, blank=True)
    Capture_traffic_time = models.DateTimeField(null=True, blank=True)

    Charts = models.CharField(max_length=255, blank=True)
    Charts_time = models.DateTimeField(null=True, blank=True)

    Csv_file_editor = models.CharField(max_length=255, blank=True)
    Csv_file_editor_time = models.DateTimeField(null=True, blank=True)

    RealTime_Traffic = models.CharField(max_length=255, blank=True)
    RealTime_Traffic_time = models.DateTimeField(null=True, blank=True)

    DDOS_Home = models.CharField(max_length=255, blank=True)
    DDOS_Home_time = models.DateTimeField(null=True, blank=True)
    
    Manual_detection = models.CharField(max_length=255, blank=True)
    Manual_detection_time = models.DateTimeField(null=True, blank=True)

    DDOS_Report = models.CharField(max_length=255, blank=True)
    DDOS_Report_time = models.DateTimeField(null=True, blank=True)

    DDOS_AI_Report = models.CharField(max_length=255, blank=True)
    DDOS_AI_Report_time = models.DateTimeField(null=True, blank=True)

    User_logout = models.CharField(max_length=255, blank=True)
    User_logout_time = models.DateTimeField(null=True, blank=True)

    Timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Log for {self.User_key.Fname} {self.User_key.Lname} at {self.Timestamp}"
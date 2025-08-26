from django.db import models

class User(models.Model):
    Fname = models.CharField(max_length=50)
    Lname = models.CharField(max_length=50)
    Dob = models.DateField()
    Age = models.IntegerField()
    Email = models.EmailField(unique=True)
    Password = models.CharField(max_length=128)
    Value = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.Fname} {self.Lname}"

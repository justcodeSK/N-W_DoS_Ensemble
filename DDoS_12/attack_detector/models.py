from django.db import models
from django.utils import timezone
from user.models import User  # Ensure this path is correct for your project

class BlockedIP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocked_ips')  # ForeignKey added
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    action = models.CharField(max_length=10, choices=[('BLOCK', 'Block'), ('UNBLOCK', 'Unblock')])
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.action} from {self.source_ip} to {self.destination_ip} by {self.user.Fname}"
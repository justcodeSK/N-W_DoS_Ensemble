# # utils.py (create in your project or app folder)

# from admins.models import UserLogs
# from django.utils import timezone

# def log_user_activity(user, field, description):
#     log, created = UserLogs.objects.create(User_key=user)

#     setattr(log, field, description)
#     setattr(log, f"{field}_time", timezone.now())

#     log.save()
# utils.py

from admins.models import UserLogs
from django.utils import timezone

def log_user_activity(user, field, description):
    # Always create a NEW log entry for each user action
    UserLogs.objects.create(
        User_key=user,
        **{
            field: description,
            f"{field}_time": timezone.now()
        }
    )

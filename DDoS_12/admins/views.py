from django.shortcuts import render, redirect
from admins.models import Admins, Contactus, UserLogs
from django.contrib import messages
from user.models import User
# Create your views here.

from django.http import JsonResponse
from django.template.loader import render_to_string
from user.models import User # assuming your model is called User
from django.views.decorators.csrf import csrf_exempt
from admins.models import Admins, UserLogs

from django.utils import timezone
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

from django.contrib.auth.hashers import make_password


def admins(request):
    admin_id = request.session.get('admin_id')
    if not admin_id:
        return redirect('home')  # or login page if not authenticated

    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'

    if not admin_obj:
        return redirect('logout')  # safety if the admin is deleted

    if request.method == "POST":
        afname = request.POST.get('afname')
        alname = request.POST.get('alname')
        adob = request.POST.get('adob')
        aage = request.POST.get('aage')
        aemail = request.POST.get('aemail')

        # Update the current admin
        admin_obj.Afname = afname
        admin_obj.Alname = alname
        admin_obj.Adob = adob
        admin_obj.Aage = aage
        admin_obj.Aemail = aemail
        admin_obj.save()

        messages.success(request, "Admin profile updated successfully.")
        return redirect("ahome")

    return render(request, 'admins.html', {'admin': admin_obj})


def admin_signup_view(request):
    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'


    if request.method == "POST":
        fname = request.POST.get("afname")
        lname = request.POST.get("alname")
        dob = request.POST.get("adob")
        age = request.POST.get("aage")
        email = request.POST.get("aemail")
        raw_password = request.POST.get("apassword")

        # Check if email already exists
        if Admins.objects.filter(Aemail=email).exists():
            messages.error(request, "Admin with this email already exists.")
            return redirect("admin_signup")

        # Create the admin with hashed password
        admin = Admins.objects.create(
            Afname=fname,
            Alname=lname,
            Adob=dob,
            Aage=age,
            Aemail=email,
            Apassword=make_password(raw_password)
        )

        # ✅ Store admin ID in session
        request.session['admin_id'] = admin.id

        messages.success(request, "Admin account created successfully.")
        return redirect("ahome")
    
    return render(request, "admin_signup.html", {'admin': admin_obj})

# other renderings
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
def ahome(request):
    if 'admin_id' not in request.session:
        return redirect('home')
    
    admin = Admins.objects.filter(id=request.session['admin_id']).first()
    if not admin:
        return redirect('logout')

    return render(request, 'ahome.html', {
        'admin': admin,
        'all_admins': Admins.objects.all()
    })
@csrf_exempt
def delete_admin(request, aid):
    if request.method == "POST" and request.headers.get("x-requested-with") == "XMLHttpRequest":
        logged_in_id = request.session.get('admin_id')
        if int(aid) == logged_in_id:
            return JsonResponse({"error": "You cannot delete your own account."}, status=403)
        try:
            Admins.objects.get(id=aid).delete()
            return JsonResponse({"success": True})
        except Admins.DoesNotExist:
            return JsonResponse({"error": "Admin not found"}, status=404)
    return JsonResponse({"error": "Invalid request"}, status=400)



def logs(request):
    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'


    # Get all logs ordered by newest first
    logs = UserLogs.objects.select_related('User_key').order_by('-Timestamp')

    # Extract unique emails
    seen_emails = set()
    unique_emails = []
    for log in logs:
        email = log.User_key.Email
        if email not in seen_emails:
            seen_emails.add(email)
            unique_emails.append(email)

    return render(request, 'logs.html', {
        'admin': admin_obj,
        'logs': logs,
        'unique_emails': unique_emails,
        'retention_value': "",
        'retention_unit': "",
    })
@csrf_exempt
def delete_log(request, log_id):
    if request.method == "POST":
        try:
            UserLogs.objects.get(id=log_id).delete()
            return JsonResponse({"success": True})
        except UserLogs.DoesNotExist:
            return JsonResponse({"error": "Log not found"}, status=404)
    return JsonResponse({"error": "Invalid request"}, status=405)
@csrf_exempt
def delete_all_logs(request):
    if request.method == "POST":
        UserLogs.objects.all().delete()
        return JsonResponse({"success": True})
    return JsonResponse({"error": "Invalid request"}, status=405)



# contactus full
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from .models import Contactus, Admins

def contactus(request):
    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'

    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        data = list(Contactus.objects.values("Cname", "Cemail", "Cphone", "Cmessage"))
        return JsonResponse(data, safe=False)

    return render(request, 'contactus.html', {
        'admin': admin_obj,
        'cus': Contactus.objects.all(),
        'retention_value': request.session.get("retention_value", 1),
        'retention_unit': request.session.get("retention_unit", "days")
    })

def delete_all_contacts(request):
    if request.method == "POST" and request.headers.get("x-requested-with") == "XMLHttpRequest":
        Contactus.objects.all().delete()
        return JsonResponse({"success": True})

    return JsonResponse({"success": False}, status=400)

def set_contact_retention(request):
    if request.method == "POST":
        value = int(request.POST.get("retention_value", 1))
        unit = request.POST.get("retention_unit", "days")
        delta_kwargs = {unit: value}
        cutoff = timezone.now() - timedelta(**delta_kwargs)
        Contactus.objects.filter(timestamp__lt=cutoff).delete()
        request.session["retention_value"] = value
        request.session["retention_unit"] = unit
    return redirect("contactus")
# end of contactus

# umanagae section
def umanage(request):
    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'

    users = User.objects.all()
    return render(request, 'umanage.html', {
        'admin': admin_obj,
        'users': users
    })
def uapprove(request, uid):
    user = User.objects.get(id=uid)
    user.Value = 1
    user.save()
    # Render only the button section
    html = render_to_string('partials/user_button.html', {'i': user})
    return JsonResponse({'buttons': html})
def deluser(request, uid):
    user = User.objects.get(id=uid)
    user.delete()
    return JsonResponse({'deleted': True, 'user_id': uid})
# umanage end




def test2(request):
    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'

    return render(request, 'test2.html', {'admin': admin_obj})



from attack_detector.models import BlockedIP
from django.views.decorators.csrf import csrf_protect

def blocked_ips(request):
    admin_id = request.session.get('admin_id')
    admin_obj = Admins.objects.filter(id=admin_id).first()
    if not admin_obj:
        return redirect('logout')  # Or 'home'
    blocked_ips = BlockedIP.objects.all().order_by('-timestamp')
    return render(request, 'blocked_ips.html', {'blocked_ips': blocked_ips,'admin': admin_obj})
@csrf_protect
def delete_all_blocked_ips(request):
    if request.method == 'POST':
        BlockedIP.objects.all().delete()
    return redirect('blocked_ips')


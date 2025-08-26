from django.shortcuts import render,redirect # type: ignore
from django import * # type: ignore
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from user.models import User
from admins.models import Contactus, Admins, UserLogs
from django.utils import timezone

from admins.utils import log_user_activity  # import the helper History Admin


# Create your views here.
def home(request):
    # return HttpResponse("hello world")
    return render(request,'index.html')
def hcontact(request):
    if request.method == "POST":
        cname = request.POST.get("cname")
        cemail = request.POST.get("cemail")
        cnum = request.POST.get("cnumber")
        cmsg = request.POST.get("cmsg")

        # ❌ Remove the email uniqueness check
        # if Contactus.objects.filter(Cemail=cemail).exists():
        #     messages.error(request, "Email already registered. Please use another email.")
        #     return redirect("hcontact")

        # ✅ Always allow saving the message
        contact = Contactus.objects.create(
            Cname=cname,
            Cemail=cemail,
            Cphone=cnum,
            Cmessage=cmsg,
        )
        contact.save()
        messages.success(request, "Message sent successfully.")
        return redirect("hcontact")
    
    return render(request, 'hcontact.html', {'contact_page': True})



def signup(request):
    if request.method == "POST":
        fname = request.POST.get("fname")
        lname = request.POST.get("lname")
        dob = request.POST.get("dob")
        age = request.POST.get("age")
        email = request.POST.get("email")
        password = request.POST.get("pass")

        if User.objects.filter(Email=email).exists():
            messages.error(request, "Email already registered. Please login or use another email.")
            return redirect("signup")

        user = User.objects.create(
            Fname=fname,
            Lname=lname,
            Dob=dob,
            Age=age,
            Email=email,
            Password=make_password(password)  # ✅ Secure Hashed
        )
        user.save()
        messages.success(request, "Account created successfully.")
        return redirect(home) 

    return render(request, 'signup.html', {'signup_page': True})


def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        # First check if it's an admin login
        try:
            admin = Admins.objects.get(Aemail=email)
            if check_password(password, admin.Apassword):
                request.session['admin_id'] = admin.id
                messages.success(request, "Admin login successful.")
                return redirect("ahome")
        except Admins.DoesNotExist:
            pass  # fall back to user login

        # User login logic (unchanged)
        try:
            user = User.objects.get(Email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not registered.")
            return redirect("home")  # your login page

        if user.Value != 1:
            messages.warning(request, "Your account is not approved yet.")
            return redirect("home")

        if check_password(password, user.Password):
            request.session['user_id'] = user.id
            messages.success(request, "Login successful.")

            user_id = request.session.get("user_id")
            user_obj = User.objects.get(id=user_id) if user_id else None
            if user_obj:
                log_user_activity(user_obj, "User_login", "User Logged-In")

            return redirect("uhome")  # your dashboard/home page
        else:
            messages.error(request, "Incorrect password.")
            return redirect("home")

    return render(request, "index.html", {'login_page': True})
  # your login page


def logout_view(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.filter(id=user_id).first()

    if user_obj:
        log_user_activity(user_obj, "User_logout", "User Logged-Out")

    # Clear session only after logging
    request.session.flush()
    messages.success(request, "Logged out successfully.")
    return redirect("login")



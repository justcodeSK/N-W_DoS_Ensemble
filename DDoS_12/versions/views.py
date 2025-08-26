from django.shortcuts import render

# Create your views here.
def versions(request):
    return render(request,'versions.html')
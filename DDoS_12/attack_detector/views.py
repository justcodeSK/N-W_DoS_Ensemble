# views.py
import json
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from .predictor import predict_attack
from django.http import JsonResponse # type: ignore
import datetime
import time
import psutil # type: ignore
from scapy.all import sniff, IP, TCP, UDP, ICMP # type: ignore
import pyshark # type: ignore
from django.http import JsonResponse
from user.models import User
from admins.utils import log_user_activity  # import the helper History Admin



# Protocol label encoding map
protocol_encoding = {
    'TCP': 0,
    'UDP': 1,
    'ICMP': 2
}

label_map_reverse = {
    0: 'BENIGN',
    1: 'SYN',
    2: 'ACK',
    3: 'RST',
    4: 'FIN',
    5: 'PSH',
    6: 'UDP',
    7: 'ICMP',
    8: 'FRAG',
    9: 'DDOS'
}

# MANUAL DETECTION
@csrf_exempt  # Only needed if you're not sending the CSRF token properly
def manual_predict_view(request):
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            # Extract values
            protocol_str = request.POST.get('protocol', '').strip().upper()
            protocol = protocol_encoding.get(protocol_str, -1)

            if protocol == -1:
                return JsonResponse({'prediction': 'Error: Unknown Protocol type'})

            # Fetch and convert other numeric features
            fields = [
                'src_port', 'length', 'payload', 'flow_duration', 'pps',
                'bps', 'inter_arrival', 'packet_id', 'frag_offset', 'icmp_type',
                'syn', 'ack', 'rst', 'fin', 'psh', 'total_packets', 'total_bytes',
                'burstiness', 'unique_dst_ports'
            ]

            features = [protocol]  # First add encoded protocol

            for field in fields:
                val = request.POST.get(field, '0').strip()
                features.append(float(val) if val else 0.0)

            # Predict
            numeric_prediction = predict_attack(features)
            prediction_label = label_map_reverse.get(numeric_prediction, f"Unknown label: {numeric_prediction}")

            return JsonResponse({'prediction': prediction_label})

        except Exception as e:
            return JsonResponse({'prediction': f"Error: {str(e)}"})

    return JsonResponse({'prediction': 'Invalid request'}, status=400)






# REAL TIME DETECTION
INTERFACES = list(psutil.net_if_addrs().keys())
flow_stats = {}

def realtime(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "RealTime_Traffic", "Visited Real-Time Detection")
    return render(request, 'realtime.html', {
        'user_obj': user_obj,
        'interfaces': INTERFACES})# included the User settings code too

@csrf_exempt
def real_time_predict_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            # Reconstruct feature vector (must match manual_predict_view feature format)
            protocol_encoding = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
            protocol = protocol_encoding.get(data.get("protocol", "").upper(), -1)
            if protocol == -1:
                return JsonResponse({"prediction": "Invalid Protocol"}, status=400)

            feature_vector = [
                protocol,
                float(data.get("src_port", 0)),
                float(data.get("length", 0)),
                float(data.get("payload_size", 0)),
                float(data.get("flow_duration", 0)),
                float(data.get("pps", 0)),
                float(data.get("bps", 0)),
                float(data.get("inter_arrival_time", 0)),
                float(data.get("packet_id", 0)),
                float(data.get("fragment_offset", 0)),
                float(data.get("icmp_type", 0)),
                float(data.get("tcp_flag_syn", 0)),
                float(data.get("tcp_flag_ack", 0)),
                float(data.get("tcp_flag_rst", 0)),
                float(data.get("tcp_flag_fin", 0)),
                float(data.get("tcp_flag_psh", 0)),
                float(data.get("total_packets", 0)),
                float(data.get("total_bytes", 0)),
                float(data.get("burstiness", 0)),
                float(data.get("unique_dst_ports", 0))
            ]

            prediction = predict_attack(feature_vector)
            label_map_reverse = {
                0: 'BENIGN', 1: 'SYN', 2: 'ACK', 3: 'RST', 4: 'FIN',
                5: 'PSH', 6: 'UDP', 7: 'ICMP', 8: 'FRAG', 9: 'DDOS'
            }
            label = label_map_reverse.get(prediction, f"Unknown: {prediction}")

            return JsonResponse({"prediction": label})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request"}, status=400)


# Gemini api code
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import google.generativeai as genai  # type: ignore

# Configure Gemini API
genai.configure(api_key="Add_Apikey_here")  # Replace with your actual API key

# views.py
@csrf_exempt
def generate_gemini_report(request):
    if request.method == "POST":
        try:
            traffic_data = json.loads(request.body)
            model = genai.GenerativeModel(model_name="gemini-2.0-flash-lite")  # Replace with actual version like 'gemini-pro'

            prompt = f"""
Analyze the following real-time network traffic data captured during a monitoring session.

1. Detect potential DDoS or DoS attack patterns.
2. Summarize traffic anomalies, IP patterns, and suspicious spikes.
3. Provide actionable mitigation recommendations.

Format the report using:
- HEADINGS in uppercase (e.g., MITIGATION RECOMMENDATIONS)
- Subheadings like 'Implement Rate Limiting' inside bullet points should be bold using <strong> tags.
- Use <p> for paragraphs and <ul><li>...</li></ul> for bullet points.
- No markdown (**), only use plain HTML.
- Separate major sections with clear line breaks.

Traffic JSON:
{json.dumps(traffic_data[:50], indent=2)}
"""

            response = model.generate_content(prompt)
            # Extract the actual response text
            report_text = response.candidates[0].content.parts[0].text
            return JsonResponse({"report": report_text})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Only POST method allowed"}, status=405)





# other render
def manual(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Manual_detection", "Visited Manual Detection")
    return render(request, 'manual.html', {'user_obj': user_obj})# included the User settings code too
def hddos(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "DDOS_Home", "Visited Dos & DDos Home Page")
    return render(request, 'hddos.html', {'user_obj': user_obj})# included the User settings code too
def report(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "DDOS_Report", "Visited Attack-Analysis Report")
    return render(request, 'report.html', {'user_obj': user_obj})# included the User settings code too
def advreport(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "DDOS_AI_Report", "Visited Advanced-Analysis Report Using AI")
    return render(request, 'advreport.html', {'user_obj': user_obj})# included the User settings code too
def ipcontrol(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Manual_detection", "Visited Manual Detection")
    return render(request, 'ipcontrol.html', {'user_obj': user_obj})# included the User settings code too    

# ip control Block code
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now
from attack_detector.models import BlockedIP
from user.models import User
import subprocess

@csrf_exempt
def block_ip(request):
    if request.method == 'POST':
        src_ip = request.POST.get("source_ip")
        dst_ip = request.POST.get("destination_ip")

        if not src_ip or not dst_ip:
            return JsonResponse({"message": "Both IPs must be provided."})

        # Check if IP is already blocked
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", src_ip, "-d", dst_ip, "-j", "DROP"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if check.returncode == 0:
            return JsonResponse({"message": f"{src_ip} is already blocked."})

        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-d", dst_ip, "-j", "DROP"],
                check=True
            )

            # Optional: capture logged-in user
            user_id = request.session.get("user_id")
            user = User.objects.get(id=user_id) if user_id else None

            BlockedIP.objects.create(
                user=user, source_ip=src_ip, destination_ip=dst_ip,
                action="BLOCK", timestamp=now()
            )
            return JsonResponse({"message": f"Blocked {src_ip} → {dst_ip}."})
        except Exception as e:
            return JsonResponse({"message": f"Error blocking: {str(e)}"})

@csrf_exempt
def unblock_ip(request):
    if request.method == 'POST':
        src_ip = request.POST.get("source_ip")
        dst_ip = request.POST.get("destination_ip")

        if not src_ip or not dst_ip:
            return JsonResponse({"message": "Both IPs must be provided."})

        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", src_ip, "-d", dst_ip, "-j", "DROP"],
                check=True
            )

            user_id = request.session.get("user_id")
            user = User.objects.get(id=user_id) if user_id else None

            BlockedIP.objects.create(
                user=user, source_ip=src_ip, destination_ip=dst_ip,
                action="UNBLOCK", timestamp=now()
            )
            return JsonResponse({"message": f"Unblocked {src_ip} → {dst_ip}."})
        except Exception as e:
            return JsonResponse({"message": f"Error unblocking: {str(e)}"})

@csrf_exempt
def history(request):
    entries = BlockedIP.objects.order_by('-timestamp')[:100]
    data = [{
        "timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "action": entry.action,
        "source_ip": entry.source_ip,
        "destination_ip": entry.destination_ip
    } for entry in entries]
    return JsonResponse(data, safe=False)

def iptracker(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Manual_detection", "Visited Manual Detection")
    return render(request, 'iptracker.html', {'user_obj': user_obj})

    


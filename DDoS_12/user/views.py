from django.shortcuts import render, redirect # type: ignore
from django.http import JsonResponse # type: ignore
import datetime
import time
import psutil # type: ignore
import statistics
from scapy.all import sniff, IP, TCP, UDP, ICMP # type: ignore
import pyshark # type: ignore
from attack_detector.predictor import predict_attack  # <-- Add at the top if not already
from user.models import User  # or the correct import

from admins.utils import log_user_activity  # import the helper History Admin


INTERFACES = list(psutil.net_if_addrs().keys())
flow_stats = {}

def nettraffic(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Capture_traffic", "Visited Capture Traffic Page")
    return render(request, 'nettraffic.html', {
        'user_obj': user_obj,
        'interfaces': INTERFACES})

# flood detection
def detect_flood(traffic_data):
    flood_threshold_pps = 1000  # example threshold for PPS (packets per second)
    flood_threshold_bps = 100000  # example threshold for BPS (bytes per second)
    flood_threshold_burst = 10  # example threshold for burst count (number of packets sent in a short duration)

    flood_alerts = []
    for packet in traffic_data:
        if packet["pps"] > flood_threshold_pps or packet["bps"] > flood_threshold_bps or packet["burstiness"] > flood_threshold_burst:
            flood_alerts.append({
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],
                "pps": packet["pps"],
                "bps": packet["bps"],
                "burstiness": packet["burstiness"],
                "alert": "Potential Flood Detected"
            })
    return flood_alerts


import threading

# Track processed flows to enrich with PyShark only once per flow
processed_flows = set()

def capture_traffic(request):
    user_iface = request.GET.get("interface", "Wi-Fi")
    traffic_data = []

    def scapy_process(pkt):
            try:
                if IP in pkt:
                    now = time.time()
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    protocol_num = pkt[IP].proto
                    protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol_num, "Other")

                    # Fix: Set ICMP fields to 0 if not present
                    icmp_type = pkt[ICMP].type if ICMP in pkt else 0
                    icmp_code = pkt[ICMP].code if ICMP in pkt else 0

                    src_port = pkt.sport if TCP in pkt or UDP in pkt else 0
                    dst_port = pkt.dport if TCP in pkt or UDP in pkt else 0
                    length = len(pkt)
                    payload_size = (len(pkt[TCP].payload.original) if TCP in pkt and hasattr(pkt[TCP], 'payload') else 
                                    (len(pkt[UDP].payload.original) if UDP in pkt and hasattr(pkt[UDP], 'payload') else 0))
                    ttl = pkt[IP].ttl
                    ip_header_length = pkt[IP].ihl * 4
                    packet_id = pkt[IP].id
                    fragment_offset = pkt[IP].frag
                    tcp_urg_ptr = pkt[TCP].urgptr if TCP in pkt else 0

                    # TCP flags — use 0/1 cleanly
                    tcp_flags = pkt[TCP].flags if TCP in pkt else 0
                    tcp_flag_fin = int(tcp_flags & 0x01 != 0) if TCP in pkt else 0
                    tcp_flag_syn = int(tcp_flags & 0x02 != 0) if TCP in pkt else 0
                    tcp_flag_rst = int(tcp_flags & 0x04 != 0) if TCP in pkt else 0
                    tcp_flag_psh = int(tcp_flags & 0x08 != 0) if TCP in pkt else 0
                    tcp_flag_ack = int(tcp_flags & 0x10 != 0) if TCP in pkt else 0
                    tcp_flag_urg = int(tcp_flags & 0x20 != 0) if TCP in pkt else 0

                    # Flow tracking
                    flow_key = (src_ip, dst_ip, protocol)
                    if flow_key not in flow_stats:
                        flow_stats[flow_key] = {
                            "start_time": now,
                            "packet_count": 0,
                            "total_bytes": 0,
                            "packet_sizes": [],
                            "dst_ports": set(),
                            "burst_count": 1,
                            "last_time": now,
                            "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
                        }

                    flow = flow_stats[flow_key]
                    flow["packet_count"] += 1
                    flow["total_bytes"] += length
                    flow["packet_sizes"].append(length)
                    flow["dst_ports"].add(dst_port)
                    flow["protocol_counts"][protocol] += 1
                    duration = now - flow["start_time"]
                    iat = now - flow["last_time"]
                    flow["last_time"] = now
                    if iat < 0.1:
                        flow["burst_count"] += 1

                    # Return the cleaned result
                    result = {
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "ttl": ttl,
                        "length": length,
                        "payload_size": payload_size,
                        "flow_duration": round(duration, 2),
                        "pps": round(flow["packet_count"] / duration, 2) if duration > 0 else 0,
                        "bps": round(flow["total_bytes"] / duration, 2) if duration > 0 else 0,
                        "inter_arrival_time": round(iat, 6) if iat is not None else 0,
                        "ip_header_length": ip_header_length,
                        "packet_id": packet_id,
                        "fragment_offset": fragment_offset,
                        "tcp_urg_ptr": tcp_urg_ptr,
                        "tcp_flag_fin": tcp_flag_fin,
                        "tcp_flag_syn": tcp_flag_syn,
                        "tcp_flag_rst": tcp_flag_rst,
                        "tcp_flag_psh": tcp_flag_psh,
                        "tcp_flag_ack": tcp_flag_ack,
                        "tcp_flag_urg": tcp_flag_urg,
                        "icmp_type": icmp_type,
                        "icmp_code": icmp_code,
                        "total_packets": flow["packet_count"],
                        "total_bytes": flow["total_bytes"],
                        "packet_size_std": round(statistics.stdev(flow["packet_sizes"]), 2) if len(flow["packet_sizes"]) > 1 else 0,
                        "burstiness": flow["burst_count"],
                        "unique_dst_ports": len(flow["dst_ports"]),
                        "info": pkt.summary() if pkt else "None"
                    }

                    return result
            except Exception as e:
                print(f"[SCAPY ERROR] {e}")
                return None


    def sniff_packets():
        return sniff(iface=user_iface, count=5, timeout=3)

    def enrich_with_pyshark(scapy_pkt_summary):
        try:
            flow_key = (scapy_pkt_summary["src_ip"], scapy_pkt_summary["dst_ip"], scapy_pkt_summary["protocol"])
            if flow_key not in processed_flows:
                cap = pyshark.LiveCapture(
                    interface=user_iface,
                    display_filter=f"ip.src=={scapy_pkt_summary['src_ip']} && ip.dst=={scapy_pkt_summary['dst_ip']}"
                )

                for pkt in cap.sniff_continuously(packet_count=1):
                    tcp_seq = 0
                    tcp_ack = 0
                    tcp_window_size = 0
                    icmp_type = 0
                    icmp_code = 0
                    info = "0"
                    dst_port = 0

                    if hasattr(pkt, 'tcp'):
                        tcp_seq = int(pkt.tcp.seq) if hasattr(pkt.tcp, 'seq') else 0
                        tcp_ack = int(pkt.tcp.ack) if hasattr(pkt.tcp, 'ack') else 0
                        tcp_window_size = int(pkt.tcp.window_size_value) if hasattr(pkt.tcp, 'window_size_value') else 0

                    if hasattr(pkt, 'icmp'):
                        icmp_type = int(pkt.icmp.type) if hasattr(pkt.icmp, 'type') else 0
                        icmp_code = int(pkt.icmp.code) if hasattr(pkt.icmp, 'code') else 0

                    if hasattr(pkt, 'highest_layer'):
                        info = pkt.highest_layer

                    if hasattr(pkt, 'tcp'):
                        dst_port = int(pkt.tcp.dstport) if hasattr(pkt.tcp, 'dstport') else 0
                    elif hasattr(pkt, 'udp'):
                        dst_port = int(pkt.udp.dstport) if hasattr(pkt.udp, 'dstport') else 0

                    # Update summary
                    scapy_pkt_summary.update({
                        "tcp_seq": tcp_seq,
                        "tcp_ack": tcp_ack,
                        "tcp_window_size": tcp_window_size,
                        "icmp_type": icmp_type,
                        "icmp_code": icmp_code,
                        "info": info,
                        "dst_port": dst_port if dst_port != 0 else scapy_pkt_summary.get("dst_port", 0)
                    })


                processed_flows.add(flow_key)

        except Exception as e:
            print(f"[PYSHARK ERROR] {e}")


    try:
        packets = sniff_packets()
        for pkt in packets:
            summary = scapy_process(pkt)
            if summary:
                enrich_with_pyshark(summary)

                try:
                    # Prepare features for ML model
                    protocol_encoding = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
                    protocol = protocol_encoding.get(summary.get("protocol", "").upper(), -1)

                    feature_vector = [
                        protocol,
                        float(summary.get("src_port", 0)),
                        float(summary.get("length", 0)),
                        float(summary.get("payload_size", 0)),
                        float(summary.get("flow_duration", 0)),
                        float(summary.get("pps", 0)),
                        float(summary.get("bps", 0)),
                        float(summary.get("inter_arrival_time", 0)),
                        float(summary.get("packet_id", 0)),
                        float(summary.get("fragment_offset", 0)),
                        float(summary.get("icmp_type", 0)),
                        float(summary.get("tcp_flag_syn", 0)),
                        float(summary.get("tcp_flag_ack", 0)),
                        float(summary.get("tcp_flag_rst", 0)),
                        float(summary.get("tcp_flag_fin", 0)),
                        float(summary.get("tcp_flag_psh", 0)),
                        float(summary.get("total_packets", 0)),
                        float(summary.get("total_bytes", 0)),
                        float(summary.get("burstiness", 0)),
                        float(summary.get("unique_dst_ports", 0))
                    ]

                    prediction_code = predict_attack(feature_vector)
                    label_map_reverse = {
                        0: 'BENIGN', 1: 'SYN', 2: 'ACK', 3: 'RST', 4: 'FIN',
                        5: 'PSH', 6: 'UDP', 7: 'ICMP', 8: 'FRAG', 9: 'DDOS'
                    }
                    summary["prediction"] = label_map_reverse.get(prediction_code, f"Unknown: {prediction_code}")
                except Exception as e:
                    summary["prediction"] = f"Prediction error: {str(e)}"

                traffic_data.append(summary)

        # Only return response after all packets are processed
        flood_alerts = detect_flood(traffic_data)
        return JsonResponse({"packets": traffic_data, "flood_alerts": flood_alerts})

    except Exception as e:
        print(f"[ERROR] Hybrid capture failed: {e}")
        return JsonResponse({"error": f"Error capturing packets: {str(e)}"})


# Other views
from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password
from user.models import User

def user(request):
    user_id = request.session.get("user_id")
    if not user_id:
        messages.error(request, "Please login first.")
        return redirect("login")

    try:
        user_obj = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect("login")

    if request.method == "POST":
        # Extract data
        fname = request.POST.get("fname")
        lname = request.POST.get("lname")
        dob = request.POST.get("dob")
        age = request.POST.get("age")
        email = request.POST.get("email")
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("password")
        confirm_password = request.POST.get("cpassword")

        # Update basic fields
        user_obj.Fname = fname
        user_obj.Lname = lname
        user_obj.Dob = dob
        user_obj.Age = age
        user_obj.Email = email

        # Password update (only if new password is filled)
        if new_password:
            if not check_password(old_password, user_obj.Password):
                messages.error(request, "Current password is incorrect.")
                return redirect("uhome")

            if new_password != confirm_password:
                messages.error(request, "New passwords do not match.")
                return redirect("uhome")

            user_obj.Password = make_password(new_password)
            messages.success(request, "Password updated successfully.")

        user_obj.save()
        # After user_obj.save()
        user_obj = User.objects.get(id=user_id) if user_id else None
        log_user_activity(user_obj, "User_settings", "User Updated Profile Data")
        messages.success(request, "Profile updated successfully.")
        return redirect("uhome")

    return render(request, 'user.html', {'user_obj': user_obj})


from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def verify_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        old_password = data.get("old_password")
        user_id = request.session.get("user_id")

        if not user_id:
            return JsonResponse({"valid": False})

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({"valid": False})

        is_valid = check_password(old_password, user.Password)
        return JsonResponse({"valid": is_valid})
    
from attack_detector.models import BlockedIP
from django.utils import timezone
def uhome(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None

    recent_threats = []
    if user_obj:
        log_user_activity(user_obj, "User_home", "Visited User Home")
        recent_threats = BlockedIP.objects.filter(user=user_obj).order_by('-timestamp')[:10]  # Latest 10

    return render(request, 'uhome.html', {
        'user_obj': user_obj,
        'recent_threats': recent_threats,
    })

def charts(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Charts", "Visited Charts Page")
    return render(request, 'charts.html', {'user_obj': user_obj})

def test(request):
    return render(request,'test.html')

def csv(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Csv_file_editor", "Visited CSV File Editor")
    return render(request, 'csv.html', {'user_obj': user_obj})
def csvmerger(request):
    user_id = request.session.get("user_id")
    user_obj = User.objects.get(id=user_id) if user_id else None
    if user_obj:
        log_user_activity(user_obj, "Csv_file_editor", "Visited CSV File Editor")
    return render(request, 'csvmerger.html', {'user_obj': user_obj})

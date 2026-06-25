from django.shortcuts import render, redirect
import re
from .models import ScanHistory

# Django auth imports (ADDED ONLY)
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

# 🔥 ADDED ONLY (for live dashboard API)
from django.http import JsonResponse


def home(request):
    return render(request, "home.html")


# ---------------- LOGIN ----------------
def login_view(request):

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("scanner")
        else:
            return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")


# ---------------- SIGNUP ----------------
def signup_view(request):

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            return render(request, "signup.html", {"error": "User already exists"})

        User.objects.create_user(username=username, password=password)

        return redirect("login")

    return render(request, "signup.html")


# ---------------- LOGOUT ----------------
def logout_view(request):
    logout(request)
    return redirect("login")


# ---------------- SCANNER ----------------
@login_required
def scanner(request):

    result = None

    if request.method == "POST":

        text = request.POST.get("text", "")

        findings = []
        risk = 0

        # Aadhaar
        aadhaar = re.findall(r'\b\d{4}\s?\d{4}\s?\d{4}\b', text)
        if aadhaar:
            for item in aadhaar:
                findings.append(f"🆔 Aadhaar: {item}")
            risk += 35

        # PAN
        pan = re.findall(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', text)
        if pan:
            for item in pan:
                findings.append(f"📄 PAN: {item}")
            risk += 30

        # Email
        email = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', text)
        if email:
            for item in email:
                findings.append(f"📧 Email: {item}")
            risk += 10

        # Mobile
        phone = re.findall(r'\b[6-9]\d{9}\b', text)
        if phone:
            for item in phone:
                findings.append(f"📱 Phone: {item}")
            risk += 15

        # UPI
        upi = re.findall(
            r'\b[\w.-]+@(?:paytm|ybl|ibl|oksbi|okaxis|okhdfcbank|upi)\b',
            text,
            re.IGNORECASE
        )
        if upi:
            for item in upi:
                findings.append(f"💸 UPI: {item}")
            risk += 15

        # IFSC
        ifsc = re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text)
        if ifsc:
            for item in ifsc:
                findings.append(f"🏦 IFSC: {item}")
            risk += 20

        # Card
        card = re.findall(r'\b\d{16}\b', text)
        if card:
            for item in card:
                findings.append(f"💳 Card: {item}")
            risk += 40

        if risk > 100:
            risk = 100

        if risk >= 70:
            level = "HIGH RISK"
        elif risk >= 40:
            level = "MEDIUM RISK"
        else:
            level = "LOW RISK"

        result = {
            "risk": risk,
            "level": level,
            "findings": findings
        }

        # SAVE TO DATABASE (UNCHANGED)
        ScanHistory.objects.create(
            text=text,
            risk=risk,
            level=level
        )

    return render(request, "scanner.html", {"result": result})


# ---------------- HISTORY ----------------
@login_required
def history(request):
    scans = ScanHistory.objects.all().order_by('-created_at')
    return render(request, "history.html", {"scans": scans})


# =========================
# 🔥 NEW: LIVE DASHBOARD API
# =========================
@login_required
def scan_api(request):
    scans = ScanHistory.objects.all().order_by('-id')[:20]

    data = {
        "labels": [str(s.id) for s in scans][::-1],
        "risk": [s.risk for s in scans][::-1],
        "level": [s.level for s in scans][::-1],
        "count": ScanHistory.objects.count()
    }

    return JsonResponse(data)
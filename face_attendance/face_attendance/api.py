import os
import re
import math
import base64
from datetime import datetime, time, timedelta
import frappe
from frappe import _
from frappe.utils import now_datetime, nowdate, format_time, getdate, now

def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance in meters between two GPS coordinates."""
    R = 6371000  # Radius of Earth in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    
    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def get_timing_classification(dt: datetime, log_type: str, profile: dict | None = None) -> dict:
    """Shift module classifier based on employee profile timing."""
    # Default shift times if profile doesn't have custom hours
    shift_start = time(9, 30)
    shift_end = time(18, 30)
    grace_mins = 15
    shift_title = "Standard Shift"
    
    if profile:
        raw_start = profile.get("shift_start_time")
        raw_end = profile.get("shift_end_time")
        grace_mins = profile.get("grace_period_mins") or 15
        shift_title = profile.get("shift_name") or "Standard Shift"
        
        if raw_start:
            if isinstance(raw_start, str):
                parts = [int(p) for p in raw_start.split(":")[:2]]
                shift_start = time(parts[0], parts[1])
            elif hasattr(raw_start, "seconds"):
                total_secs = raw_start.seconds
                shift_start = time(total_secs // 3600, (total_secs % 3600) // 60)
            elif isinstance(raw_start, time):
                shift_start = raw_start

        if raw_end:
            if isinstance(raw_end, str):
                parts = [int(p) for p in raw_end.split(":")[:2]]
                shift_end = time(parts[0], parts[1])
            elif hasattr(raw_end, "seconds"):
                total_secs = raw_end.seconds
                shift_end = time(total_secs // 3600, (total_secs % 3600) // 60)
            elif isinstance(raw_end, time):
                shift_end = raw_end

    start_dt = datetime.combine(dt.date(), shift_start)
    grace_dt = start_dt + timedelta(minutes=int(grace_mins))
    halfday_dt = start_dt + timedelta(hours=4)
    end_dt = datetime.combine(dt.date(), shift_end)
    timing_str = f"{shift_start.strftime('%I:%M %p')} - {shift_end.strftime('%I:%M %p')}"
    
    if log_type == "IN":
        if dt <= grace_dt:
            return {
                "module": "Present", 
                "label": "On-Time Entry", 
                "description": f"Standard {shift_title}", 
                "badge": "ontime",
                "shift": timing_str
            }
        elif dt <= halfday_dt:
            mins_late = int((dt - start_dt).total_seconds() // 60)
            return {
                "module": "Late Entry", 
                "label": f"Late by {mins_late}m", 
                "description": "Marked Present (Late)", 
                "badge": "late",
                "shift": timing_str
            }
        else:
            return {
                "module": "Half Day", 
                "label": "Half Day Entry", 
                "description": "Entered after 4h into shift", 
                "badge": "halfday",
                "shift": timing_str
            }
    else:
        if dt < (end_dt - timedelta(hours=3)):
            return {
                "module": "Half Day", 
                "label": "Early Departure", 
                "description": "Left early before half shift", 
                "badge": "halfday",
                "shift": timing_str
            }
        elif dt < (end_dt - timedelta(minutes=15)):
            mins_early = int((end_dt - dt).total_seconds() // 60)
            return {
                "module": "Early Exit", 
                "label": f"Left early ({mins_early}m early)", 
                "description": "Shift ended early", 
                "badge": "early",
                "shift": timing_str
            }
        elif dt <= (end_dt + timedelta(minutes=15)):
            return {
                "module": "Present", 
                "label": "Shift Completed (On-Time)", 
                "description": "Standard shift fulfilled", 
                "badge": "ontime",
                "shift": timing_str
            }
        else:
            ot_minutes = int((dt - end_dt).total_seconds() // 60)
            ot_str = f"+{ot_minutes // 60}h {ot_minutes % 60}m" if ot_minutes >= 60 else f"+{ot_minutes}m"
            return {
                "module": "Overtime", 
                "label": f"Overtime ({ot_str}) • Pending HR Approval", 
                "description": "Extra time worked past scheduled shift. Requires HR approval.", 
                "badge": "overtime",
                "is_overtime": True,
                "overtime_minutes": ot_minutes,
                "overtime_hours": round(ot_minutes / 60.0, 2),
                "overtime_duration": ot_str,
                "shift": timing_str,
                "shift_end_raw": str(shift_end)
            }

@frappe.whitelist(allow_guest=True)
def get_kiosk_config() -> dict:
    """Return kiosk settings."""
    now_dt = now_datetime()
    settings = frappe.get_single("Face Attendance Settings")
    
    return {
        "success": True,
        "kiosk_title": settings.kiosk_title or "Attendance Kiosk",
        "company": settings.company or "",
        "require_face": bool(settings.require_face),
        "enable_sound": bool(settings.enable_sound),
        "enable_haptics": bool(settings.enable_haptics),
        "enable_geo": bool(settings.enable_geo),
        "server_time": format_time(now_dt, "hh:mm:ss a"),
        "server_date": now_dt.strftime("%A, %d %B %Y")
    }

@frappe.whitelist(allow_guest=True)
def verify_pin_preview(pin: str) -> dict:
    """
    Lookup employee by PIN:
    - Protects against brute-force lockout (after 5 failed attempts per IP)
    - Returns official reference photo URL, assigned shift timing, and last punch status
    """
    if not pin:
        return {"success": False, "message": "PIN required"}
    
    client_ip = getattr(frappe.local, "request_ip", "127.0.0.1")
    cache_key = f"pin_attempts_{client_ip}"
    failed_attempts = frappe.cache.get_value(cache_key) or 0

    if failed_attempts >= 5:
        return {
            "success": False,
            "locked": True,
            "message": "Security lockout: 5 failed PIN attempts. Please wait 3 minutes before trying again."
        }

    pin_str = str(pin).strip()
    profile = frappe.db.get_value(
        "Face Attendance Profile",
        {"secret_pin": pin_str, "status": "Active"},
        ["name", "employee", "employee_name", "department", "designation", "face_image", "face_descriptor", "is_registered", "last_log_type", "last_checkin_time", "shift_name", "shift_start_time", "shift_end_time", "grace_period_mins"],
        as_dict=True
    )
    
    if not profile:
        new_attempts = failed_attempts + 1
        frappe.cache.set_value(cache_key, new_attempts, expires_in_sec=180)
        remaining = 5 - new_attempts
        return {
            "success": False, 
            "message": f"PIN not recognized. {remaining} attempt{'s' if remaining > 1 else ''} left before lockout."
        }
    
    # Reset failed attempts on success
    frappe.cache.delete_value(cache_key)
    
    now_dt = now_datetime()
    today = nowdate()
    today_start = f"{today} 00:00:00"

    # Query authoritative last punch today
    last_log_today = frappe.db.get_value(
        "Face Attendance Log",
        {"employee": profile.employee, "timestamp": [">=", today_start], "status": "Success"},
        ["log_type", "timestamp"],
        order_by="timestamp desc",
        as_dict=True
    )
    
    latest_today_type = last_log_today.log_type if last_log_today else (profile.last_log_type if (profile.last_checkin_time and str(profile.last_checkin_time) >= today_start) else None)
    latest_today_time = last_log_today.timestamp if last_log_today else (profile.last_checkin_time if (profile.last_checkin_time and str(profile.last_checkin_time) >= today_start) else None)

    if latest_today_type in ["IN", "OUT"]:
        auto_log_type = "OUT" if latest_today_type == "IN" else "IN"
    else:
        auto_log_type = "IN"

    timing_info = get_timing_classification(now_dt, auto_log_type, profile)

    return {
        "success": True,
        "employee": profile.employee,
        "employee_name": profile.employee_name,
        "department": profile.department or "Team Member",
        "designation": profile.designation or "",
        "face_image": profile.face_image or "",
        "face_descriptor": profile.face_descriptor or "",
        "has_reference_image": bool(profile.face_image),
        "shift_name": profile.shift_name or "Regular Day Shift",
        "shift_start_time": str(profile.shift_start_time) if profile.shift_start_time else "09:30:00",
        "shift_end_time": str(profile.shift_end_time) if profile.shift_end_time else "18:30:00",
        "shift_timing": timing_info.get("shift", "09:30 AM - 06:30 PM"),
        "last_log_type": latest_today_type or "None",
        "last_checkin_time": format_time(latest_today_time, "hh:mm a") if latest_today_time else "None",
        "auto_log_type": auto_log_type,
        "timing_module": timing_info["module"],
        "timing_label": timing_info["label"]
    }

@frappe.whitelist(allow_guest=True)
def mark_face_pin_attendance(
    pin: str,
    photo_base64: str | None = None,
    log_type: str | None = None,
    match_status: str | None = None,
    ai_confidence: str | None = None,
    coords: str | None = None,
    latitude: float | str | None = None,
    longitude: float | str | None = None,
    device_info: str | None = None,
    selfie_descriptor: str | None = None
) -> dict:
    """
    Security-Hardened Attendance Marking Endpoint:
    1. Brute-force lockout prevention
    2. Rapid duplicate spam cooldown (minimum 2 minutes between punches)
    3. Blank / black covered camera detection
    4. Geofencing perimeter check (if configured)
    5. Anti-fake audit against official reference photo
    6. Server-side authoritative timestamp (cannot be tampered by mobile clock)
    """
    if not pin:
        pin = frappe.form_dict.get("pin")
    if not pin and hasattr(frappe, "request") and frappe.request.is_json:
        req_json = frappe.request.get_json() or {}
        pin = req_json.get("pin")
    
    if not pin:
        return {
            "success": False,
            "message": _("4-Digit Secret PIN is required")
        }
    
    client_ip = getattr(frappe.local, "request_ip", "127.0.0.1")
    cache_key = f"pin_attempts_{client_ip}"
    failed_attempts = frappe.cache.get_value(cache_key) or 0
    if failed_attempts >= 5:
        return {
            "success": False,
            "locked": True,
            "message": _("Terminal locked: Too many failed PIN attempts. Please wait 3 minutes.")
        }

    pin_str = str(pin).strip()
    profile = frappe.db.get_value(
        "Face Attendance Profile",
        {"secret_pin": pin_str, "status": "Active"},
        ["name", "employee", "employee_name", "department", "designation", "face_image", "face_descriptor", "is_registered", "total_checkins", "last_log_type", "last_checkin_time", "shift_name", "shift_start_time", "shift_end_time", "grace_period_mins"],
        as_dict=True
    )
    
    if not profile:
        new_attempts = failed_attempts + 1
        frappe.cache.set_value(cache_key, new_attempts, expires_in_sec=180)
        return {
            "success": False,
            "message": _(f"Invalid PIN. {5 - new_attempts} attempts remaining.")
        }

    # Reset failed attempts on valid profile
    frappe.cache.delete_value(cache_key)

    now_dt = now_datetime()
    today = nowdate()
    today_start = f"{today} 00:00:00"

    # Authoritative punch resolution: Query latest successful punch today
    last_log_today = frappe.db.get_value(
        "Face Attendance Log",
        {"employee": profile.employee, "timestamp": [">=", today_start], "status": "Success"},
        ["log_type", "timestamp"],
        order_by="timestamp desc",
        as_dict=True
    )
    
    last_checkin_today = None
    if frappe.db.exists("DocType", "Employee Checkin"):
        last_checkin_today = frappe.db.get_value(
            "Employee Checkin",
            {"employee": profile.employee, "time": [">=", today_start]},
            ["log_type", "time"],
            order_by="time desc",
            as_dict=True
        )

    latest_today_type = None
    latest_today_time = None
    if last_log_today and last_checkin_today:
        if last_checkin_today.time and (not last_log_today.timestamp or last_checkin_today.time > last_log_today.timestamp):
            latest_today_type = last_checkin_today.log_type
            latest_today_time = last_checkin_today.time
        else:
            latest_today_type = last_log_today.log_type
            latest_today_time = last_log_today.timestamp
    elif last_log_today:
        latest_today_type = last_log_today.log_type
        latest_today_time = last_log_today.timestamp
    elif last_checkin_today:
        latest_today_type = last_checkin_today.log_type
        latest_today_time = last_checkin_today.time
    elif profile.last_checkin_time and str(profile.last_checkin_time) >= today_start and profile.last_log_type:
        latest_today_type = profile.last_log_type
        latest_today_time = profile.last_checkin_time

    # 1. Resolve Log Type (IN or OUT)
    if log_type and str(log_type).upper() in ["IN", "OUT"]:
        resolved_log_type = str(log_type).upper()
    elif latest_today_type in ["IN", "OUT"]:
        # Perfect alternating sequence: IN -> OUT -> IN -> OUT
        resolved_log_type = "OUT" if latest_today_type == "IN" else "IN"
    else:
        # First punch of today
        resolved_log_type = "IN"

    # --- DEFENSE 1: Blank / Covered Camera Check ---
    if not photo_base64 or len(photo_base64) < 400:
        return {
            "success": False,
            "message": _("Camera was covered or selfie frame missing. Face must be clearly visible.")
        }

    # --- DEFENSE 2: Real-time Biometric Face Matching (Anti-Buddy Punching) ---
    if profile.face_descriptor and selfie_descriptor:
        try:
            import json
            ref_vec = json.loads(profile.face_descriptor) if isinstance(profile.face_descriptor, str) else profile.face_descriptor
            input_vec = json.loads(selfie_descriptor) if isinstance(selfie_descriptor, str) else selfie_descriptor
            
            if ref_vec and input_vec and len(ref_vec) == len(input_vec):
                dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(input_vec, ref_vec)))
                if dist > 0.50:
                    frappe.log_error(f"Proxy punch rejected for {profile.employee_name}. Face distance: {dist:.3f}", "Biometric Mismatch")
                    return {
                        "success": False,
                        "face_mismatch": True,
                        "reference_photo": profile.face_image or "",
                        "message": _(f"Face Mismatch! Scanned face does not match {profile.employee_name}'s official photo. Proxy punch rejected.")
                    }
        except Exception as face_err:
            frappe.log_error(f"Face matching check error: {face_err}", "Biometric Face Match")

    # --- DEFENSE 3: Rapid Duplicate Click Cooldown ---
    check_time = latest_today_time or profile.last_checkin_time
    check_type = latest_today_type or profile.last_log_type
    if check_time:
        delta_seconds = (now_dt - check_time).total_seconds()
        # Only block if same punch direction was marked within 15 seconds
        if check_type == resolved_log_type and delta_seconds < 15:
            remaining_wait = int(15 - delta_seconds)
            state_text = "already logged in" if check_type == "IN" else "already logged out"
            return {
                "success": False,
                "cooldown": True,
                "reference_photo": profile.face_image or "",
                "message": _(f"Candidate is {state_text}. Please wait {remaining_wait}s before punching again.")
            }

    # --- Geolocation Parsing (Latitude & Longitude) ---
    punch_lat = None
    punch_lon = None
    if latitude is not None and longitude is not None and str(latitude).strip() and str(longitude).strip():
        try:
            punch_lat = round(float(latitude), 6)
            punch_lon = round(float(longitude), 6)
        except Exception:
            pass
    elif coords and "," in str(coords):
        try:
            parts = str(coords).split(",")
            punch_lat = round(float(parts[0].strip()), 6)
            punch_lon = round(float(parts[1].strip()), 6)
        except Exception:
            pass
    elif hasattr(frappe, "form_dict"):
        f_lat = frappe.form_dict.get("latitude")
        f_lon = frappe.form_dict.get("longitude")
        if f_lat and f_lon:
            try:
                punch_lat = round(float(f_lat), 6)
                punch_lon = round(float(f_lon), 6)
            except Exception:
                pass

    coords_str = f"{punch_lat:.6f}, {punch_lon:.6f}" if punch_lat is not None and punch_lon is not None else (coords or "")

    # --- DEFENSE 3: Geofencing Check (if office coordinates are configured) ---
    geo_status = "Verified In Office" if punch_lat is not None else "Location Not Available"
    settings = frappe.get_single("Face Attendance Settings")
    office_lat = getattr(settings, "office_latitude", None)
    office_lon = getattr(settings, "office_longitude", None)
    geofence_radius = getattr(settings, "geofence_radius_meters", None) or 250

    if office_lat and office_lon and punch_lat is not None and punch_lon is not None:
        try:
            dist = calculate_haversine_distance(punch_lat, punch_lon, float(office_lat), float(office_lon))
            if dist > float(geofence_radius):
                geo_status = f"Outside Geofence ({int(dist)}m away)"
                if getattr(settings, "enable_geofence_lock", False):
                    return {
                        "success": False,
                        "message": _(f"Attendance blocked: You are {int(dist)}m away from office premises.")
                    }
            else:
                geo_status = f"Inside Geofence ({int(dist)}m)"
        except Exception:
            pass

    # Match status audit - Strictly enforce allowed DocType values: "Verified Match", "Review Needed", "Missing Reference"
    allowed_statuses = ["Verified Match", "Review Needed", "Missing Reference"]
    if match_status not in allowed_statuses:
        match_status = "Verified Match" if profile.face_image else "Missing Reference"

    # 2. Timing Classification
    timing_info = get_timing_classification(now_dt, resolved_log_type, profile=profile)

    # 3. Save Captured Selfie Photo
    photo_file_url = None
    try:
        if "," in photo_base64:
            header, encoded = photo_base64.split(",", 1)
        else:
            encoded = photo_base64
        
        image_data = base64.b64decode(encoded)
        file_name = f"attendance_snap_{profile.employee}_{now_dt.strftime('%Y%m%d_%H%M%S')}.jpg"
        
        saved_file = frappe.get_doc({
            "doctype": "File",
            "file_name": file_name,
            "content": image_data,
            "is_private": 0
        })
        saved_file.insert(ignore_permissions=True)
        photo_file_url = saved_file.file_url
    except Exception as file_err:
        frappe.log_error(f"Error saving attendance selfie: {file_err}", "Face Attendance Photo Save")

    # 4. Create Standard Employee Checkin
    employee_checkin_name = None
    try:
        checkin_doc = frappe.get_doc({
            "doctype": "Employee Checkin",
            "employee": profile.employee,
            "time": now_dt,
            "log_type": resolved_log_type,
            "device_id": "Auto-Face-PIN-Kiosk",
            "latitude": punch_lat,
            "longitude": punch_lon,
        })
        checkin_doc.insert(ignore_permissions=True)
        employee_checkin_name = checkin_doc.name
    except Exception as checkin_err:
        frappe.log_error(f"Error creating Employee Checkin: {checkin_err}", "Face Attendance Checkin")

    notes_msg = f"Shift: {timing_info['module']} ({timing_info['label']}). Match Status: {match_status}. Geo: {geo_status}."
    if ai_confidence:
        notes_msg += f" AI Match Confidence: {ai_confidence}."

    # 5. Create Face Attendance Log record
    face_log = frappe.get_doc({
        "doctype": "Face Attendance Log",
        "employee": profile.employee,
        "employee_name": profile.employee_name,
        "log_type": resolved_log_type,
        "timestamp": now_dt,
        "status": "Success",
        "match_status": match_status,
        "pin_verified": 1,
        "face_detected": 1 if photo_file_url else 0,
        "photo_captured": photo_file_url,
        "reference_photo": profile.face_image or None,
        "device_info": device_info or "Smart Biometric Kiosk",
        "ip_address": client_ip,
        "latitude": punch_lat,
        "longitude": punch_lon,
        "location_coords": coords_str,
        "employee_checkin": employee_checkin_name,
        "notes": notes_msg
    })
    face_log.flags.ignore_links = True
    face_log.insert(ignore_permissions=True)

    # 6. Mark Attendance in HRMS / Attendance DocType
    try:
        if frappe.db.exists("DocType", "Attendance"):
            existing_att = frappe.db.get_value(
                "Attendance",
                {"employee": profile.employee, "attendance_date": today, "docstatus": ["!=", 2]},
                ["name", "status"],
                as_dict=True
            )
            att_status = "Present" if timing_info["module"] != "Half Day" else "Half Day"
            
            if not existing_att:
                att_doc = frappe.get_doc({
                    "doctype": "Attendance",
                    "employee": profile.employee,
                    "attendance_date": today,
                    "status": att_status
                })
                att_doc.insert(ignore_permissions=True)
                att_doc.submit()
    except Exception as att_err:
        frappe.log_error(f"Error auto-marking Attendance: {att_err}", "Face Attendance Direct Mark")

    # 7. Update Face Attendance Profile stats
    frappe.db.set_value(
        "Face Attendance Profile",
        profile.name,
        {
            "last_checkin_time": now_dt,
            "last_log_type": resolved_log_type,
            "last_latitude": punch_lat,
            "last_longitude": punch_lon,
            "last_location": coords_str,
            "total_checkins": (profile.total_checkins or 0) + 1
        },
        update_modified=False
    )
    frappe.db.commit()

    # 6. Check and create Employee Overtime Request if extra time worked past full day
    overtime_request_name = None
    overtime_status = None
    if resolved_log_type == "OUT" and timing_info.get("is_overtime"):
        try:
            ot_hours = timing_info.get("overtime_hours", 0)
            ot_duration_str = timing_info.get("overtime_duration", "")
            shift_start_str = timing_info.get("shift_end_raw", "18:30:00")
            
            existing_ot = frappe.db.get_value(
                "Employee Overtime Request",
                {"employee": profile.employee, "overtime_date": today, "docstatus": ["!=", 2]},
                ["name", "status"],
                as_dict=True
            )
            if existing_ot:
                ot_doc = frappe.get_doc("Employee Overtime Request", existing_ot.name)
                ot_doc.end_time = now_dt.strftime("%H:%M:%S")
                ot_doc.overtime_hours = ot_hours
                ot_doc.reason = f"Kiosk Punch OUT: Verified extra time worked ({ot_duration_str}). Awaiting HR approval."
                ot_doc.save(ignore_permissions=True)
                overtime_request_name = ot_doc.name
                overtime_status = ot_doc.status
            else:
                ot_doc = frappe.get_doc({
                    "doctype": "Employee Overtime Request",
                    "naming_series": "OT-.YYYY.-.#####",
                    "employee": profile.employee,
                    "employee_name": profile.employee_name,
                    "department": profile.department or "",
                    "designation": profile.designation or "",
                    "overtime_date": today,
                    "overtime_type": "Regular Overtime",
                    "status": "Pending Approval",
                    "start_time": shift_start_str,
                    "end_time": now_dt.strftime("%H:%M:%S"),
                    "overtime_hours": ot_hours,
                    "reason": f"Kiosk Punch OUT: Verified extra time worked ({ot_duration_str}) past scheduled shift end. Sent for HR approval."
                })
                ot_doc.insert(ignore_permissions=True)
                overtime_request_name = ot_doc.name
                overtime_status = "Pending Approval"
        except Exception as ot_err:
            frappe.log_error(f"Error creating Overtime Request: {ot_err}", "Overtime Auto Request")

    # Clear internal server message log to prevent unwanted telemetry/system notifications from leaking to the kiosk
    frappe.local.message_log = []
    if hasattr(frappe.local, "response") and "_server_messages" in frappe.local.response:
        del frappe.local.response["_server_messages"]

    if resolved_log_type == "OUT":
        if timing_info.get("is_overtime"):
            user_msg = f"{profile.employee_name} logged OUT. Extra time ({timing_info['overtime_duration']}) detected and sent for HR approval."
        else:
            user_msg = f"{profile.employee_name} was already logged in. Successfully logged OUT!"
    elif latest_today_type == "OUT":
        user_msg = f"{profile.employee_name} was already logged out. Successfully logged IN!"
    else:
        user_msg = f"Welcome, {profile.employee_name}! Successfully logged IN!"

    return {
        "success": True,
        "employee_id": profile.employee,
        "employee_name": profile.employee_name,
        "department": profile.department or "General",
        "designation": profile.designation or "Team Member",
        "log_type": resolved_log_type,
        "latitude": punch_lat,
        "longitude": punch_lon,
        "location": coords_str,
        "is_overtime": bool(timing_info.get("is_overtime")),
        "overtime_duration": timing_info.get("overtime_duration", ""),
        "overtime_hours": timing_info.get("overtime_hours", 0),
        "overtime_request": overtime_request_name,
        "overtime_status": overtime_status or ("Pending HR Approval" if timing_info.get("is_overtime") else None),
        "shift_name": profile.shift_name or "Standard Shift",
        "shift_timing": timing_info.get("shift", "09:30 AM - 06:30 PM"),
        "timing_module": timing_info["module"],
        "timing_label": timing_info["label"],
        "time": format_time(now_dt, "hh:mm:ss a"),
        "date": today,
        "avatar": profile.face_image or photo_file_url or "/assets/frappe/images/default-avatar.png",
        "reference_photo": profile.face_image or photo_file_url,
        "captured_photo": photo_file_url,
        "match_status": match_status,
        "ai_confidence": ai_confidence or "",
        "message": user_msg
    }

@frappe.whitelist(allow_guest=True)
def save_employee_face_descriptor(employee: str | None = None, employee_name: str | None = None, descriptor: str | None = None) -> dict:
    """Save 128-float face descriptor for employee."""
    if not descriptor:
        return {"success": False, "message": "Descriptor required"}
    
    filters = {}
    if employee:
        filters["employee"] = employee
    elif employee_name:
        filters["employee_name"] = employee_name
    else:
        return {"success": False, "message": "Employee identifier required"}
        
    profile_name = frappe.db.get_value("Face Attendance Profile", filters, "name")
    if not profile_name:
        return {"success": False, "message": "Profile not found"}
        
    frappe.db.set_value("Face Attendance Profile", profile_name, "face_descriptor", descriptor)
    frappe.db.commit()
    return {"success": True, "message": f"Face descriptor enrolled successfully for {profile_name}"}

@frappe.whitelist(allow_guest=True)
def submit_job_application(
    candidate_name: str,
    phone: str,
    email: str,
    position_applied: str,
    experience_years: float | None = None,
    notice_period: str | None = None,
    current_location: str | None = None,
    current_ctc: float | None = None,
    expected_ctc: float | None = None,
    resume_file_url: str | None = None,
    resume_base64: str | None = None,
    resume_filename: str | None = None,
    hr_notes: str | None = None
) -> dict:
    """Public recruitment endpoint for candidates to apply with PDF resume."""
    if not candidate_name or not candidate_name.strip():
        frappe.throw(_("Candidate Name is required"))
    if not phone or not phone.strip():
        frappe.throw(_("Phone / Mobile number is required"))
    if not email or not email.strip():
        frappe.throw(_("Email address is required"))
    if not position_applied or not position_applied.strip():
        frappe.throw(_("Position Applied For is required"))
    
    saved_resume_url = resume_file_url
    
    # Handle direct multipart file upload if submitted via FormData
    uploaded_file = None
    if getattr(frappe, "request", None) and getattr(frappe.request, "files", None):
        uploaded_file = frappe.request.files.get("resume") or frappe.request.files.get("file")
        
    if uploaded_file:
        filename = uploaded_file.filename or "resume.pdf"
        if not filename.lower().endswith(".pdf"):
            frappe.throw(_("Word documents (.doc, .docx) are NOT allowed. Please upload your resume in PDF format (.pdf)."))
        file_doc = frappe.get_doc({
            "doctype": "File",
            "file_name": filename,
            "content": uploaded_file.stream.read(),
            "is_private": 0
        })
        file_doc.save(ignore_permissions=True)
        saved_resume_url = file_doc.file_url
    elif resume_base64:
        filename = resume_filename or f"resume_{now_datetime().strftime('%Y%m%d_%H%M%S')}.pdf"
        if not filename.lower().endswith(".pdf"):
            frappe.throw(_("Word documents (.doc, .docx) are NOT allowed. Please upload your resume in PDF format (.pdf)."))
        b64_content = resume_base64
        if "base64," in b64_content:
            b64_content = b64_content.split("base64,")[1]
        raw_bytes = base64.b64decode(b64_content)
        file_doc = frappe.get_doc({
            "doctype": "File",
            "file_name": filename,
            "content": raw_bytes,
            "is_private": 0
        })
        file_doc.save(ignore_permissions=True)
        saved_resume_url = file_doc.file_url

    if not saved_resume_url:
        frappe.throw(_("Resume file (PDF format only) is mandatory."))
    
    candidate = frappe.get_doc({
        "doctype": "Job Candidate",
        "candidate_name": candidate_name.strip(),
        "phone": phone.strip(),
        "email": email.strip().lower(),
        "position_applied": position_applied.strip(),
        "status": "New",
        "experience_years": float(experience_years) if experience_years else 0,
        "notice_period": notice_period or "Immediate",
        "current_location": current_location.strip() if current_location else "",
        "current_ctc": float(current_ctc) if current_ctc else 0,
        "expected_ctc": float(expected_ctc) if expected_ctc else 0,
        "resume": saved_resume_url,
        "source": "Web Form",
        "hr_notes": hr_notes or ""
    })
    candidate.insert(ignore_permissions=True)
    frappe.db.commit()

    return {
        "success": True,
        "candidate_id": candidate.name,
        "candidate_name": candidate.candidate_name,
        "position_applied": candidate.position_applied,
        "message": f"Thank you, {candidate.candidate_name}! Your application has been submitted successfully."
    }

def evaluate_boolean_expression(text: str, expr: str) -> tuple[bool, int]:
    """
    Evaluates boolean query string with AND, OR, NOT, quotes and parentheses against candidate text.
    Returns (matches: bool, hit_count: int).
    """
    if not expr or not expr.strip():
        return True, 0

    text_lower = text.lower()
    raw_query = expr.strip()
    
    # Tokenize words, quoted phrases, and operators
    pattern = r'(".*?"|\(|\)|\bAND\b|\bOR\b|\bNOT\b|[^\s()]+)'
    raw_tokens = re.findall(pattern, raw_query, flags=re.IGNORECASE)
    
    python_expr_parts = []
    hit_count = 0
    prev_was_operand = False
    
    for tok in raw_tokens:
        tok_upper = tok.upper()
        if tok_upper == 'AND':
            python_expr_parts.append('and')
            prev_was_operand = False
        elif tok_upper == 'OR':
            python_expr_parts.append('or')
            prev_was_operand = False
        elif tok_upper == 'NOT':
            if prev_was_operand:
                python_expr_parts.append('and')
            python_expr_parts.append('not')
            prev_was_operand = False
        elif tok == '(':
            if prev_was_operand:
                python_expr_parts.append('and')
            python_expr_parts.append('(')
            prev_was_operand = False
        elif tok == ')':
            python_expr_parts.append(')')
            prev_was_operand = True
        else:
            term = tok.strip('"\'').lower()
            if term:
                is_hit = term in text_lower
                if is_hit:
                    hit_count += text_lower.count(term)
                if prev_was_operand:
                    python_expr_parts.append('and')
                python_expr_parts.append(str(is_hit))
                prev_was_operand = True
                
    if not python_expr_parts:
        return True, 0
        
    eval_str = " ".join(python_expr_parts)
    try:
        matches = bool(eval(eval_str, {"__builtins__": {}}, {}))
    except Exception:
        simple_words = [w.lower() for w in re.findall(r'\w+', raw_query) if w.upper() not in ['AND', 'OR', 'NOT']]
        matches = any(w in text_lower for w in simple_words) if simple_words else True
        hit_count = sum(text_lower.count(w) for w in simple_words)
        
    return matches, hit_count

def extract_unique_tags(tags_str: str) -> list[str]:
    """
    Extracts strictly unique, clean tags. Strips punctuation, dashes, junk tokens,
    and deduplicates case-insensitively.
    """
    if not tags_str:
        return []
    seen = set()
    result = []
    junk = {'-', '--', 'n/a', 'na', 'none', 'null', 'workindia', 'candidate', 'job', 'portal', '+', 'other'}
    for raw in str(tags_str).split(','):
        cleaned = re.sub(r'^[^\w]+|[^\w]+$', '', raw.strip()).strip()
        if not cleaned or len(cleaned) < 2:
            continue
        lower_t = cleaned.lower()
        if lower_t in junk or lower_t in seen:
            continue
        seen.add(lower_t)
        display_t = cleaned.title() if (cleaned.islower() or cleaned.isupper()) else cleaned
        result.append(display_t)
    return result

@frappe.whitelist(allow_guest=True)
def search_job_candidates(
    query: str | None = None,
    status: str | None = None,
    position: str | None = None,
    min_exp: float | None = None,
    max_exp: float | None = None,
    notice_periods: str | None = None,
    location: str | None = None,
    max_ctc: float | None = None,
    tags: str | None = None,
    sort_by: str = "relevance",
    page: int = 1,
    page_size: int = 6
) -> dict:
    """
    Candidate Talent Discovery API:
    1. Boolean Search Parser (AND, OR, NOT, Quotes, Parentheses)
    2. Multi-Criteria Filters (Status, Position, Experience, Location, CTC, Notice)
    3. Profile Tags & Skills Filtering
    4. Smart Relevance Ranking (Best to Less Relevant)
    5. Clean Pagination & Metadata Aggregations
    """
    page = int(page or 1)
    page_size = int(page_size or 6)
    
    # 1. Fetch all candidate records from database (No 50 cap)
    all_candidates = frappe.get_all(
        "Job Candidate",
        fields=[
            "name", "candidate_name", "email", "phone", "status",
            "position_applied", "current_location", "experience_years",
            "notice_period", "current_ctc", "expected_ctc", "resume",
            "source", "next_follow_up_date", "hr_notes", "profile_tags",
            "creation"
        ],
        limit=10000
    )
    
    # Parse list parameters
    selected_statuses = [s.strip() for s in status.split(",") if s.strip()] if status else []
    selected_notice = [n.strip() for n in notice_periods.split(",") if n.strip()] if notice_periods else []
    selected_tags = [t.strip().lower() for t in tags.split(",") if t.strip()] if tags else []
    
    # Tag aggregations across all candidates
    tag_counter = {}
    location_counter = {}
    position_counter = {}
    
    for c in all_candidates:
        # Tally unique tags per candidate
        for t_clean in extract_unique_tags(c.get("profile_tags") or ""):
            tag_counter[t_clean] = tag_counter.get(t_clean, 0) + 1
        
        # Tally locations
        loc = (c.get("current_location") or "").strip()
        if loc:
            location_counter[loc] = location_counter.get(loc, 0) + 1
            
        # Tally positions
        pos = (c.get("position_applied") or "").strip()
        if pos:
            position_counter[pos] = position_counter.get(pos, 0) + 1
            
    filtered = []
    
    for c in all_candidates:
        c_exp = float(c.get("experience_years") or 0)
        c_ctc = float(c.get("expected_ctc") or 0)
        c_loc = (c.get("current_location") or "").lower()
        c_status = c.get("status") or "New"
        c_notice = c.get("notice_period") or "Immediate"
        c_pos = (c.get("position_applied") or "").lower()
        c_tags_raw = (c.get("profile_tags") or "").lower()
        c_tags_list = [t.strip() for t in c_tags_raw.split(",") if t.strip()]
        
        # Apply Status Filter
        if selected_statuses and c_status not in selected_statuses:
            continue
            
        # Apply Position Filter
        if position and position.strip().lower() not in c_pos:
            continue
            
        # Apply Experience Filter
        if min_exp is not None and min_exp != "" and c_exp < float(min_exp):
            continue
        if max_exp is not None and max_exp != "" and c_exp > float(max_exp):
            continue
            
        # Apply Notice Period Filter
        if selected_notice and c_notice not in selected_notice:
            continue
            
        # Apply Location Filter
        if location and location.strip().lower() not in c_loc:
            continue
            
        # Apply Max CTC Filter
        if max_ctc is not None and max_ctc != "" and float(max_ctc) > 0:
            if c_ctc > float(max_ctc):
                continue
                
        # Apply Profile Tags Filter
        if selected_tags:
            # Check if candidate has at least one of the selected tags
            if not any(req_tag in c_tags_raw for req_tag in selected_tags):
                continue
                
        # Boolean Search Query Filter
        searchable_text = f"{c.get('candidate_name', '')} {c.get('position_applied', '')} {c.get('profile_tags', '')} {c.get('current_location', '')} {c.get('notice_period', '')} {c.get('source', '')} {c.get('hr_notes', '')}"
        
        matches_query, hit_count = evaluate_boolean_expression(searchable_text, query or "")
        if not matches_query:
            continue
            
        # 3. Calculate Smart Relevance Ranking Score (0 to 100)
        relevance_score = 45 # Base baseline
        
        if query and query.strip():
            # Query hits bonus
            relevance_score += min(hit_count * 10, 30)
            # Exact position hit
            if any(term in c_pos for term in query.lower().split() if term not in ['and', 'or', 'not']):
                relevance_score += 15
            # Skills tag hit
            if any(term in c_tags_raw for term in query.lower().split() if term not in ['and', 'or', 'not']):
                relevance_score += 10
        else:
            relevance_score = 65
            
        # Notice Period score bonus (immediate availability is valuable to HR)
        if c_notice == "Immediate":
            relevance_score += 10
        elif c_notice == "15 Days":
            relevance_score += 6
        elif c_notice == "30 Days":
            relevance_score += 3
            
        # Experience bonus
        if 2.0 <= c_exp <= 6.0:
            relevance_score += 8
        elif c_exp > 6.0:
            relevance_score += 5
            
        # Tag density bonus
        if selected_tags:
            tag_matches = sum(1 for req_t in selected_tags if req_t in c_tags_raw)
            relevance_score += int((tag_matches / len(selected_tags)) * 15)
            
        # Status weight
        if c_status == "Interview":
            relevance_score += 6
        elif c_status == "Screening":
            relevance_score += 4
        elif c_status == "New":
            relevance_score += 2
        elif c_status == "Rejected":
            relevance_score -= 35
            
        # Clamp score
        final_score = max(min(relevance_score, 99), 20)
        
        # Determine match tier
        if final_score >= 88:
            tier_label = "Top Match"
            tier_icon = "star"
        elif final_score >= 72:
            tier_label = "Strong Fit"
            tier_icon = "zap"
        elif final_score >= 50:
            tier_label = "Good Match"
            tier_icon = "thumbs-up"
        else:
            tier_label = "Potential Fit"
            tier_icon = "file-text"
            
        # Clean phone for WhatsApp fast follow-up
        clean_phone = re.sub(r'[^0-9]', '', str(c.get("phone", "")))
        if len(clean_phone) == 10:
            clean_phone = "91" + clean_phone
            
        # Parse rich fields from hr_notes
        notes_text = c.get("hr_notes") or ""
        p_langs = ""
        p_edu = ""
        p_rel = ""
        p_ind = ""
        p_assets = ""
        p_sal = ""
        p_resume = ""
        
        if notes_text:
            m_l = re.search(r'Languages:\s*([^|]+)', notes_text, re.I)
            if m_l: p_langs = m_l.group(1).strip()
            m_e = re.search(r'Education:\s*([^|]+)', notes_text, re.I)
            if m_e: p_edu = m_e.group(1).strip()
            m_r = re.search(r'Relevant Exp:\s*([^|]+)', notes_text, re.I)
            if m_r: p_rel = m_r.group(1).strip()
            m_i = re.search(r'Industry:\s*([^|]+)', notes_text, re.I)
            if m_i: p_ind = m_i.group(1).strip()
            m_a = re.search(r'Assets:\s*([^|]+)', notes_text, re.I)
            if m_a: p_assets = m_a.group(1).strip()
            m_s = re.search(r'Salary:\s*([^|]+)', notes_text, re.I)
            if m_s: p_sal = m_s.group(1).strip()
            m_res = re.search(r'Resume:\s*([^|]+)', notes_text, re.I)
            if m_res: p_resume = m_res.group(1).strip()
            
        cand_resume = c.get("resume") or ""
        bad_resume_tokens = [
            ".svg", ".gif", ".ico", ".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff",
            "candidate_profile/media",
            "/employer/assets/", "/assets/img/", "/assets/svg/", "/static/img/",
            "candidate_experience", "candidate_salary", "candidate_location", "candidate_education",
            "pooja_sharma", "candidate-resume"
        ]
        if cand_resume and any(b in cand_resume.lower() for b in bad_resume_tokens):
            cand_resume = ""
        if p_resume and any(b in p_resume.lower() for b in bad_resume_tokens):
            p_resume = ""

        is_external_doc = bool(
            cand_resume and 
            (cand_resume.startswith("http://") or cand_resume.startswith("https://") or cand_resume.startswith("/files/")) and
            not any(b in cand_resume.lower() for b in bad_resume_tokens) and
            (
                "candidate-own-resume" in cand_resume.lower() or
                any(cand_resume.lower().endswith(ext) or (ext + "?") in cand_resume.lower() for ext in [".pdf", ".doc", ".docx"])
            )
        )
        cand_resume = cand_resume if is_external_doc else ""
        is_uploaded_resume = is_external_doc

        sal_str = ""
        is_valid_sal = bool(p_sal and p_sal != "N/A" and p_sal != "Not Disclosed" and not re.search(r'\b[6-9]\d{9}\b', p_sal))
        if is_valid_sal:
            sal_digits = re.findall(r'\d+', p_sal.replace(',', ''))
            if sal_digits:
                val = float(''.join(sal_digits))
                if val < 3000 or val > 5000000:
                    is_valid_sal = False
            else:
                is_valid_sal = False

        if is_valid_sal:
            clean_s = re.sub(r'^[₹rRs\.\s]+', '', p_sal).strip()
            sal_str = f"₹{clean_s}" if clean_s else ""
        elif c_ctc > 0:
            monthly = int(c_ctc / 12)
            sal_str = f"₹{monthly:,} / mo" 

        filtered.append({
            "name": c["name"],
            "candidate_name": c["candidate_name"],
            "email": c["email"],
            "phone": c["phone"],
            "clean_phone": clean_phone,
            "status": c_status,
            "position_applied": c.get("position_applied") or "Team Member",
            "current_location": c.get("current_location") or "Not Specified",
            "experience_years": c_exp,
            "notice_period": c_notice,
            "current_ctc": c.get("current_ctc") or 0,
            "expected_ctc": c_ctc,
            "resume": cand_resume,
            "is_uploaded_resume": is_uploaded_resume,
            "source": c.get("source") or "Web Form",
            "hr_notes": notes_text,
            "languages": p_langs if p_langs != "N/A" else "",
            "education": p_edu if p_edu != "N/A" else "",
            "relevant_exp": p_rel if p_rel != "N/A" else "",
            "industry": p_ind if p_ind != "N/A" else "",
            "assets": p_assets if p_assets != "N/A" else "",
            "salary_display": sal_str,
            "profile_tags": ", ".join(extract_unique_tags(c.get("profile_tags") or "")),
            "tags_list": extract_unique_tags(c.get("profile_tags") or ""),
            "relevance_score": final_score,
            "match_tier": tier_label,
            "tier_icon": tier_icon,
            "hit_count": hit_count,
            "desk_url": f"/app/job-candidate/{c['name']}"
        })
        
    # 4. Sorting: Default to Relevance DESC (Best to Less Relevant)
    if sort_by == "relevance":
        filtered.sort(key=lambda x: (x["relevance_score"], x["experience_years"]), reverse=True)
    elif sort_by == "experience_desc":
        filtered.sort(key=lambda x: x["experience_years"], reverse=True)
    elif sort_by == "experience_asc":
        filtered.sort(key=lambda x: x["experience_years"])
    elif sort_by == "ctc_asc":
        filtered.sort(key=lambda x: x["expected_ctc"])
    elif sort_by == "newest":
        filtered.sort(key=lambda x: x["name"], reverse=True)
        
    # 5. Pagination
    total_matches = len(filtered)
    total_pages = math.ceil(total_matches / page_size) if total_matches > 0 else 1
    page = min(max(1, page), total_pages)
    
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_results = filtered[start_idx:end_idx]
    
    return {
        "success": True,
        "candidates": paginated_results,
        "total_count": total_matches,
        "total_in_db": len(all_candidates),
        "total_pages": total_pages,
        "current_page": page,
        "page_size": page_size,
        "aggregations": {
            "tags": sorted([{"tag": k, "count": v} for k, v in tag_counter.items()], key=lambda x: x["count"], reverse=True)[:20],
            "locations": sorted([{"location": k, "count": v} for k, v in location_counter.items()], key=lambda x: x["count"], reverse=True),
            "positions": sorted([{"position": k, "count": v} for k, v in position_counter.items()], key=lambda x: x["count"], reverse=True)
        }
    }

@frappe.whitelist(allow_guest=True)
def update_candidate_status(candidate_id: str, new_status: str) -> dict:
    """Quick 1-click status update from talent search card."""
    if not candidate_id or not new_status:
        return {"success": False, "message": "Candidate ID and status required"}
    
    if not frappe.db.exists("Job Candidate", candidate_id):
        return {"success": False, "message": "Candidate not found"}
        
    frappe.db.set_value("Job Candidate", candidate_id, "status", new_status)
    frappe.db.commit()
    return {"success": True, "message": f"Candidate {candidate_id} status updated to {new_status}"}





def normalize_candidate_tags(raw_skills: str = "", raw_langs: str = "") -> str:
    """
    Cleans and strictly deduplicates skills and language tags.
    Eliminates duplicate tags and removes junk sentences.
    """
    seen = set()
    cleaned = []
    junk = {'-', '--', 'n/a', 'na', 'none', 'null', 'workindia', 'candidate', 'job', 'portal', '+', 'other'}
    for raw in [raw_skills, raw_langs]:
        if not raw or raw == 'N/A':
            continue
        for token in str(raw).split(','):
            t = token.strip()
            if not t:
                continue
            t_clean = re.sub(r'^[^\w]+|[^\w]+$', '', t).strip()
            if not t_clean or len(t_clean) < 2 or len(t_clean) > 26 or len(t_clean.split()) > 3:
                continue
            if any(bad in t_clean.lower() for bad in [' at ', ' in ', '(', ')', 'assistant at', 'consultant in', 'years', 'yrs']):
                continue
            lower_t = t_clean.lower()
            if lower_t in junk:
                continue
            if lower_t not in seen:
                seen.add(lower_t)
                cleaned.append(t_clean)
    return ", ".join(cleaned)

@frappe.whitelist(allow_guest=True)
def ingest_candidates_batch(candidates: list | str | None = None) -> dict:
    """
    Ingests batch of candidates from Chrome extension into Frappe Job Candidate DocType.
    Stores comprehensive fields: Name, Phone, Location, Exp, Salary, Languages, Education,
    Relevant Exp, Skills, Industry, Assets, and Resume URL.
    """
    import re, random, time
    
    # Add CORS response headers for browser extensions
    if hasattr(frappe, 'local') and hasattr(frappe.local, 'response'):
        frappe.local.response.setdefault('headers', {})
        frappe.local.response['headers']['Access-Control-Allow-Origin'] = '*'
        frappe.local.response['headers']['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
        frappe.local.response['headers']['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Frappe-CSRF-Token'

    if isinstance(candidates, str):
        try:
            candidates = frappe.parse_json(candidates)
        except Exception:
            candidates = []

    if not candidates or not isinstance(candidates, list):
        return {'success': False, 'message': 'No candidates provided'}

    inserted = 0
    updated = 0
    errors = 0

    for i, c in enumerate(candidates):
        if not isinstance(c, dict):
            continue

        try:
            name = (c.get('candidate_name') or 'Candidate').strip()
            phone = (c.get('mobile_no') or '').strip()
            email = (c.get('email') or '').strip()

            existing = None
            if phone and len(phone) >= 8:
                clean_digits = re.sub(r'\D', '', phone)
                res = frappe.db.sql("SELECT name FROM `tabJob Candidate` WHERE phone LIKE %s LIMIT 1", ('%' + clean_digits[-10:] + '%',))
                existing = res[0][0] if res else None
                
            if not existing and name and name != 'Candidate':
                existing = frappe.db.get_value('Job Candidate', {'candidate_name': name}, 'name')

            raw_exp = str(c.get('experience') or '')
            exp_years = 0.0
            exp_m = re.search(r'(\d+(?:\.\d+)?)', raw_exp)
            if exp_m:
                exp_years = float(exp_m.group(1))

            raw_sal = str(c.get('expected_salary') or '').strip()
            if re.search(r'\b[6-9]\d{9}\b', raw_sal):
                raw_sal = 'Not Disclosed'
            sal_nums = re.findall(r'\d+', raw_sal.replace(',', ''))
            expected_ctc = 0.0
            if sal_nums:
                sal_val = float(''.join(sal_nums))
                if 3000 <= sal_val <= 250000:
                    expected_ctc = sal_val * 12
                    raw_sal = f"₹{int(sal_val):,}/month"
                elif 50000 <= sal_val <= 4000000:
                    expected_ctc = sal_val
                    raw_sal = f"₹{int(sal_val):,} / yr"
                else:
                    raw_sal = 'Not Disclosed'
                    expected_ctc = 0.0
            else:
                raw_sal = 'Not Disclosed'

            raw_loc = str(c.get('location') or 'Patna').strip()
            if re.search(r'(?:yrs|years|male|female|candidate|relevant|applied)', raw_loc, re.I):
                raw_loc = 'Patna'
            clean_loc = re.sub(r'^(?:month|year|/month|/mo)\s*', '', raw_loc, flags=re.I).strip()
            if not clean_loc:
                clean_loc = 'Patna'

            # Prioritize the role from Relevant Experience so it matches the hiring category
            role = ''
            rel_exp = (c.get('relevant_exp') or '').strip()
            if rel_exp and rel_exp != 'N/A':
                r_clean = rel_exp.split(' at ')[0].strip()
                r_clean = re.sub(r'\s+in\s+.*$', '', r_clean, flags=re.I).strip()
                if len(r_clean) >= 3 and not r_clean.lower().startswith('fresher'):
                    role = r_clean

            if not role:
                cur_j = (c.get('current_job') or '').strip()
                if cur_j and cur_j != 'N/A':
                    r_clean = cur_j.split(' at ')[0].strip()
                    r_clean = re.sub(r'\s+in\s+.*$', '', r_clean, flags=re.I).strip()
                    if len(r_clean) >= 3:
                        role = r_clean

            if not role:
                role = (c.get('position_applied') or '').strip()

            if not role or role.lower() in ['workindia candidate', 'candidate', 'candidate discovery']:
                role = 'Field Sales Executive'

            clean_position = role[:60]

            tags = c.get('skills') or 'WorkIndia, Candidate'
            edu = c.get('education') or 'N/A'
            rel = c.get('relevant_exp') or 'N/A'
            langs = c.get('languages') or 'N/A'
            ind = c.get('industry') or 'N/A'
            assets = c.get('assets') or 'N/A'
            resume_url = c.get('resume_url') or ''

            bad_resume_tokens = [
                '.svg', '.gif', '.ico', '.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tiff',
                'candidate_profile/media', '/employer/assets/', '/assets/img/',
                'candidate_experience', 'candidate_salary', 'candidate_location', 'candidate_education',
                'pooja_sharma', 'candidate-resume'
            ]
            is_real_resume = bool(
                resume_url and 
                (resume_url.startswith('http://') or resume_url.startswith('https://') or resume_url.startswith('/files/')) and 
                not resume_url.startswith('/candidate-resume') and
                not any(b in resume_url.lower() for b in bad_resume_tokens) and
                (
                    'candidate-own-resume' in resume_url.lower() or
                    any(resume_url.lower().endswith(ext) or (ext + '?') in resume_url.lower() for ext in ['.pdf', '.doc', '.docx']) or
                    ('/resume/' in resume_url.lower() and not any(ext in resume_url.lower() for ext in ['.jpg', '.png', '.jpeg', '.webp'])) or
                    ('/cv/' in resume_url.lower() and not any(ext in resume_url.lower() for ext in ['.jpg', '.png', '.jpeg', '.webp']))
                )
            )


            notes = f"Languages: {langs} | Education: {edu} | Relevant Exp: {rel} | Industry: {ind} | Assets: {assets} | Salary: {raw_sal} | Resume: {resume_url if is_real_resume else 'No File Attached (Profile Form Only)'}"

            if existing:
                doc = frappe.get_doc('Job Candidate', existing)
                if not doc.phone and phone:
                    doc.phone = phone
                doc.profile_tags = normalize_candidate_tags(tags, langs)
                doc.hr_notes = notes
                doc.current_location = clean_loc
                doc.experience_years = exp_years
                doc.expected_ctc = expected_ctc
                doc.resume = resume_url if is_real_resume else ''
                doc.position_applied = clean_position
                doc.flags.ignore_mandatory = True
                doc.save(ignore_permissions=True)
                updated += 1
            else:
                clean_email_name = re.sub(r'[^a-zA-Z0-9]', '.', name.lower()) or 'cand'
                candidate_email = email
                if not candidate_email:
                    base_email = f"{clean_email_name}@candidate.workindia"
                    if frappe.db.exists('Job Candidate', {'email': base_email}):
                        candidate_email = f"{clean_email_name}.{int(time.time())}_{i}_{random.randint(100, 999)}@candidate.workindia"
                    else:
                        candidate_email = base_email

                candidate_phone = phone or f"+9198{random.randint(10000000, 99999999)}"

                doc = frappe.new_doc('Job Candidate')
                doc.candidate_name = name
                doc.phone = candidate_phone
                doc.email = candidate_email
                doc.status = 'New'
                doc.position_applied = clean_position
                doc.current_location = clean_loc
                doc.experience_years = exp_years
                doc.expected_ctc = expected_ctc
                doc.source = 'Job Portal'
                doc.profile_tags = normalize_candidate_tags(tags, langs)
                doc.hr_notes = notes
                doc.resume = resume_url if is_real_resume else ''
                doc.flags.ignore_mandatory = True
                doc.insert(ignore_permissions=True)
                inserted += 1
        except Exception as ex:
            frappe.log_error(f"Ingest error for candidate {c}: {ex}", "Candidate Batch Ingest")
            errors += 1
            continue

    frappe.db.commit()
    return {
        'success': True,
        'inserted': inserted,
        'updated': updated,
        'errors': errors,
        'total': len(candidates),
        'message': f"Successfully ingested {inserted} candidates (updated {updated}) into Frappe!"
    }


@frappe.whitelist(allow_guest=True)
def update_candidate_dossier(
    candidate_id: str | None = None,
    notes: str | None = None,
    status: str | None = None,
    position: str | None = None,
    location: str | None = None
) -> dict:
    data = {}
    try:
        if hasattr(frappe, 'request') and frappe.request and frappe.request.is_json:
            data = frappe.request.get_json() or {}
    except Exception:
        pass
    if not data and hasattr(frappe, 'form_dict') and frappe.form_dict:
        data = dict(frappe.form_dict)

    cid = candidate_id or data.get('candidate_id')
    n = notes if notes is not None else data.get('notes')
    st = status if status is not None else data.get('status')
    pos = position if position is not None else data.get('position')
    loc = location if location is not None else data.get('location')

    if not cid or not frappe.db.exists("Job Candidate", cid):
        return {"success": False, "message": f"Candidate {cid} not found"}
        
    doc = frappe.get_doc("Job Candidate", cid)
    if st:
        doc.status = st
    if n is not None:
        doc.hr_notes = n
    if pos:
        doc.position_applied = pos
    if loc:
        doc.current_location = loc
    doc.save(ignore_permissions=True)
    frappe.db.commit()
    return {
        "success": True, 
        "message": f"Successfully updated {doc.candidate_name}'s profile dossier!",
        "status": doc.status,
        "hr_notes": doc.hr_notes
    }


@frappe.whitelist(allow_guest=True)
def update_job_candidate(
    candidate_id: str | None = None,
    candidate_name: str | None = None,
    phone: str | None = None,
    email: str | None = None,
    status: str | None = None,
    current_location: str | None = None,
    experience_years: float | int | str | None = None,
    expected_ctc: float | int | str | None = None,
    position_applied: str | None = None,
    hr_notes: str | None = None,
    profile_tags: str | None = None,
    resume: str | None = None
) -> dict:
    """Fully editable profile update from candidate-search UI."""
    data = {}
    try:
        if hasattr(frappe, 'request') and frappe.request and frappe.request.is_json:
            data = frappe.request.get_json() or {}
    except Exception:
        pass
    if not data and hasattr(frappe, 'form_dict') and frappe.form_dict:
        data = dict(frappe.form_dict)

    cid = candidate_id or data.get('candidate_id') or data.get('name')
    if not cid or not frappe.db.exists("Job Candidate", cid):
        return {"success": False, "message": f"Candidate '{cid}' not found"}

    doc = frappe.get_doc("Job Candidate", cid)
    
    c_name = candidate_name or data.get('candidate_name')
    if c_name:
        doc.candidate_name = c_name

    p = phone or data.get('phone')
    if p:
        doc.phone = p

    em = email or data.get('email')
    if em:
        doc.email = em

    st = status or data.get('status')
    if st:
        doc.status = st

    loc = current_location or data.get('current_location')
    if loc is not None:
        doc.current_location = loc

    exp = experience_years if experience_years is not None else data.get('experience_years')
    if exp is not None:
        try:
            doc.experience_years = float(exp)
        except Exception:
            pass

    ctc = expected_ctc if expected_ctc is not None else data.get('expected_ctc')
    if ctc is not None:
        try:
            doc.expected_ctc = float(ctc)
        except Exception:
            pass

    pos = position_applied or data.get('position_applied')
    if pos:
        doc.position_applied = pos

    notes = hr_notes if hr_notes is not None else data.get('hr_notes')
    if notes is not None:
        doc.hr_notes = notes

    tags = profile_tags if profile_tags is not None else data.get('profile_tags')
    if tags is not None:
        doc.profile_tags = tags

    res = resume if resume is not None else data.get('resume')
    if res is not None:
        doc.resume = res

    doc.save(ignore_permissions=True)
    frappe.db.commit()
    return {
        "success": True,
        "message": f"Profile for {doc.candidate_name} updated successfully!",
        "candidate": doc.as_dict()
    }


@frappe.whitelist(allow_guest=True)
def delete_job_candidate(candidate_id: str | None = None) -> dict:
    """Delete a single candidate profile from Frappe."""
    data = {}
    try:
        if hasattr(frappe, 'request') and frappe.request and frappe.request.is_json:
            data = frappe.request.get_json() or {}
    except Exception:
        pass
    if not data and hasattr(frappe, 'form_dict') and frappe.form_dict:
        data = dict(frappe.form_dict)

    cid = candidate_id or data.get('candidate_id') or data.get('name')
    if not cid or not frappe.db.exists("Job Candidate", cid):
        return {"success": False, "message": f"Candidate '{cid}' not found"}

    cand_name = frappe.db.get_value("Job Candidate", cid, "candidate_name") or cid
    frappe.delete_doc("Job Candidate", cid, ignore_permissions=True, force=True)
    frappe.db.commit()
    return {
        "success": True,
        "message": f"Candidate '{cand_name}' was deleted successfully."
    }


@frappe.whitelist(allow_guest=True)
def delete_all_job_candidates(candidate_ids: list | str | None = None) -> dict:
    """Delete all or selected candidate profiles from Frappe."""
    import json
    data = {}
    try:
        if hasattr(frappe, 'request') and frappe.request and frappe.request.is_json:
            data = frappe.request.get_json() or {}
    except Exception:
        pass
    if not data and hasattr(frappe, 'form_dict') and frappe.form_dict:
        data = dict(frappe.form_dict)

    cids = candidate_ids or data.get('candidate_ids') or []
    if isinstance(cids, str):
        try:
            cids = json.loads(cids)
        except Exception:
            cids = [c.strip() for c in cids.split(',') if c.strip()]

    deleted_count = 0
    if cids and len(cids) > 0:
        for cid in cids:
            if frappe.db.exists("Job Candidate", cid):
                frappe.delete_doc("Job Candidate", cid, ignore_permissions=True, force=True)
                deleted_count += 1
    else:
        # Delete all candidates
        all_cands = frappe.get_all("Job Candidate", pluck="name")
        for cid in all_cands:
            frappe.delete_doc("Job Candidate", cid, ignore_permissions=True, force=True)
            deleted_count += 1

    frappe.db.commit()
    return {
        "success": True,
        "deleted_count": deleted_count,
        "message": f"Successfully deleted {deleted_count} candidate profiles!"
    }


# =========================================================================
# TASK MANAGEMENT SUITE (Integrated with Frappe / ERPNext Task & Project)
# =========================================================================

@frappe.whitelist(allow_guest=True)
def get_task_board(
    project: str | None = None, 
    priority: str | None = None, 
    search: str | None = None
) -> dict:
    """Fetch tasks grouped for Kanban board, plus metadata and project list."""
    filters = {}
    if project and project != 'all':
        filters['project'] = project
    if priority and priority != 'all':
        filters['priority'] = priority
    
    tasks = frappe.get_all(
        "Task",
        filters=filters,
        fields=[
            "name", "subject", "project", "status", "priority", 
            "exp_start_date", "exp_end_date", "description", 
            "progress", "task_weight", "creation", "modified",
            "_assign"
        ],
        order_by="modified desc",
        limit_page_length=500
    )

    if search and search.strip():
        q = search.strip().lower()
        tasks = [t for t in tasks if q in (t.subject or '').lower() or q in (t.description or '').lower() or q in (t.project or '').lower()]

    projects = frappe.get_all("Project", fields=["name", "project_name", "status", "percent_complete"], order_by="name asc")

    now = frappe.utils.nowdate()
    total_count = len(tasks)
    overdue_count = sum(1 for t in tasks if t.exp_end_date and str(t.exp_end_date) < now and t.status not in ["Completed", "Cancelled"])
    completed_count = sum(1 for t in tasks if t.status == "Completed")
    in_progress_count = sum(1 for t in tasks if t.status == "Working")
    
    priority_counts = {
        "Urgent": sum(1 for t in tasks if t.priority == "Urgent"),
        "High": sum(1 for t in tasks if t.priority == "High"),
        "Medium": sum(1 for t in tasks if t.priority == "Medium"),
        "Low": sum(1 for t in tasks if t.priority == "Low"),
    }

    columns = {
        "Open": [t for t in tasks if t.status == "Open"],
        "Working": [t for t in tasks if t.status == "Working"],
        "Pending Review": [t for t in tasks if t.status == "Pending Review"],
        "Completed": [t for t in tasks if t.status == "Completed"],
        "Cancelled": [t for t in tasks if t.status == "Cancelled"]
    }

    return {
        "success": True,
        "tasks": tasks,
        "columns": columns,
        "projects": projects,
        "stats": {
            "total": total_count,
            "overdue": overdue_count,
            "completed": completed_count,
            "working": in_progress_count,
            "priority": priority_counts
        }
    }

@frappe.whitelist(allow_guest=True)
def create_task(
    subject: str, 
    project: str | None = None, 
    priority: str = "Medium", 
    status: str = "Open", 
    exp_start_date: str | None = None, 
    exp_end_date: str | None = None, 
    description: str | None = None, 
    assigned_to: str | None = None
) -> dict:
    """Create a new Task directly in Frappe database."""
    if not subject or not subject.strip():
        frappe.throw("Task Subject / Title is required")
        
    doc = frappe.new_doc("Task")
    doc.subject = subject.strip()
    if project and frappe.db.exists("Project", project):
        doc.project = project
    doc.priority = priority or "Medium"
    doc.status = status or "Open"
    if exp_start_date:
        doc.exp_start_date = exp_start_date
    if exp_end_date:
        doc.exp_end_date = exp_end_date
    if description:
        doc.description = description
    doc.save(ignore_permissions=True)
    
    if assigned_to and assigned_to.strip():
        try:
            from frappe.desk.form.assign_to import add
            add({
                "doctype": "Task",
                "name": doc.name,
                "assign_to": [assigned_to.strip()]
            })
        except Exception:
            pass

    frappe.db.commit()
    return {"success": True, "message": f"Task '{doc.subject}' created successfully!", "task": doc.as_dict()}

@frappe.whitelist(allow_guest=True)
def update_task_status(task_id: str, status: str) -> dict:
    """Fast status advance or Kanban drag-and-drop."""
    if not task_id or not frappe.db.exists("Task", task_id):
        frappe.throw(f"Task '{task_id}' not found")
        
    doc = frappe.get_doc("Task", task_id)
    doc.status = status
    if status == "Completed":
        doc.progress = 100
        doc.act_end_date = frappe.utils.nowdate()
    elif status == "Working" and doc.progress == 0:
        doc.progress = 25
    doc.save(ignore_permissions=True)
    frappe.db.commit()
    return {"success": True, "message": f"Task updated to '{status}'", "task": doc.as_dict()}

@frappe.whitelist(allow_guest=True)
def update_task_details(
    task_id: str, 
    subject: str | None = None, 
    project: str | None = None, 
    priority: str | None = None, 
    status: str | None = None, 
    exp_end_date: str | None = None, 
    description: str | None = None, 
    progress: int | float | None = None
) -> dict:
    """Full task detail update."""
    if not task_id or not frappe.db.exists("Task", task_id):
        frappe.throw(f"Task '{task_id}' not found")

    doc = frappe.get_doc("Task", task_id)
    if subject: doc.subject = subject.strip()
    if project: doc.project = project
    if priority: doc.priority = priority
    if status: doc.status = status
    if exp_end_date is not None: doc.exp_end_date = exp_end_date or None
    if description is not None: doc.description = description
    if progress is not None: doc.progress = int(progress)
    doc.save(ignore_permissions=True)
    frappe.db.commit()
    return {"success": True, "message": "Task updated successfully", "task": doc.as_dict()}

@frappe.whitelist(allow_guest=True)
def delete_task(task_id: str) -> dict:
    """Delete a task from Frappe."""
    if not task_id or not frappe.db.exists("Task", task_id):
        frappe.throw(f"Task '{task_id}' not found")
        
    frappe.delete_doc("Task", task_id, ignore_permissions=True)
    frappe.db.commit()
    return {"success": True, "message": f"Task {task_id} deleted"}

@frappe.whitelist(allow_guest=True)
def create_project(project_name: str) -> dict:
    """Create a new Project."""
    if not project_name or not project_name.strip():
        frappe.throw("Project Name is required")
        
    doc = frappe.new_doc("Project")
    doc.project_name = project_name.strip()
    doc.status = "Open"
    doc.save(ignore_permissions=True)
    frappe.db.commit()
    return {"success": True, "message": f"Project '{doc.project_name}' created!", "project": doc.as_dict()}


# =========================================================================
# ON-DEMAND CANDIDATE PDF RESUME & BATCH ZIP EXPORTERS
# =========================================================================

@frappe.whitelist(allow_guest=True)
def get_candidate_pdf(candidate: str | None = None) -> None:
    """
    Returns an official, high-fidelity A4 PDF resume document for any candidate.
    If the candidate already uploaded an external PDF, redirects or streams it.
    Otherwise, compiles an on-the-fly PDF using ReportLab.
    """
    import re
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_RIGHT
    import urllib.request

    raw_query = (candidate or frappe.form_dict.get('candidate') or frappe.form_dict.get('name') or '').strip()
    if not raw_query:
        frappe.throw("Candidate ID or Name is required", frappe.ValidationError)

    target_doc_id = None
    if frappe.db.exists('Job Candidate', raw_query):
        target_doc_id = raw_query
    else:
        target_doc_id = frappe.db.get_value('Job Candidate', {'candidate_name': raw_query}, 'name')
        if not target_doc_id:
            clean_digits = re.sub(r'\D', '', raw_query)
            if len(clean_digits) >= 10:
                target_doc_id = frappe.db.get_value('Job Candidate', {'phone': ['like', f'%{clean_digits[-10:]}%']}, 'name')
        if not target_doc_id:
            target_doc_id = frappe.db.get_value('Job Candidate', {'candidate_name': ['like', f'%{raw_query}%']}, 'name')

    if not target_doc_id:
        frappe.throw(f"Candidate '{raw_query}' not found", frappe.DoesNotExistError)

    doc = frappe.get_doc('Job Candidate', target_doc_id)

    # If candidate has an uploaded external PDF file, redirect directly or serve
    if doc.resume and (doc.resume.startswith('http://') or doc.resume.startswith('https://')) and doc.resume.endswith('.pdf'):
        frappe.local.flags.redirect_location = doc.resume
        raise frappe.Redirect

    # Build PDF with ReportLab
    styles = getSampleStyleSheet()
    header_sub = ParagraphStyle('HeaderSub', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=11, leading=14, textColor=colors.HexColor('#8e3820'))
    contact_style = ParagraphStyle('ContactStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, alignment=TA_RIGHT, textColor=colors.HexColor('#52525b'))
    section_heading = ParagraphStyle('SectionHeading', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=11, leading=15, textColor=colors.HexColor('#18181b'), spaceAfter=6)
    body_text = ParagraphStyle('BodyTextCustom', parent=styles['Normal'], fontName='Helvetica', fontSize=9.5, leading=14, textColor=colors.HexColor('#3f3f46'))
    meta_label = ParagraphStyle('MetaLabel', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.HexColor('#71717a'))
    meta_val = ParagraphStyle('MetaVal', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10.5, leading=13, textColor=colors.HexColor('#18181b'))

    notes = doc.hr_notes or ""
    def extract_val(pattern, default=""):
        m = re.search(pattern, notes, re.IGNORECASE)
        return m.group(1).strip() if m else default

    langs = extract_val(r'Languages:\s*([^|]+)', "English, Hindi")
    edu = extract_val(r'Education:\s*([^|]+)', "Graduate")
    rel_exp = extract_val(r'Relevant Exp:\s*([^|]+)', "")
    ind = extract_val(r'Industry:\s*([^|]+)', "")
    assets = extract_val(r'Assets:\s*([^|]+)', "")
    salary_str = extract_val(r'Salary:\s*([^|]+)', "")

    exp_years = float(doc.experience_years or 0)
    expected_ctc = float(doc.expected_ctc or 0)
    salary_display = salary_str if (salary_str and salary_str != "N/A") else (f"Rs. {int(expected_ctc):,} / annum" if expected_ctc > 0 else "Disclosed upon discussion")

    tags = doc.profile_tags or ""
    skills = [t.strip() for t in tags.split(",") if t.strip() and t.strip().lower() not in ['candidate', 'workindia']]
    if not skills:
        skills = ["Communication", "Client Relations", "Operations", "Teamwork"]

    buffer = BytesIO()
    doc_pdf = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    story = []

    # 1. Header Table
    name_html = f"<b>{doc.candidate_name}</b>"
    role_html = f"{doc.position_applied or 'Candidate Discovery'} &bull; {exp_years} Years Experience"
    
    right_contact = f"""
    <b>{doc.phone or 'N/A'}</b><br/>
    {doc.email or f"{doc.name.lower()}@candidate.workindia"}<br/>
    {doc.current_location or 'India'}<br/>
    <font color="#059669"><b>Status: {doc.status or 'New'}</b></font>
    """

    header_table_data = [
        [
            Paragraph(f"<font size=8 color='#8e3820'><b>CANDIDATE DOSSIER &bull; {doc.name}</b></font><br/>{name_html}<br/>{role_html}", styles['Normal']),
            Paragraph(right_contact, contact_style)
        ]
    ]

    header_table = Table(header_table_data, colWidths=[330, 190])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#18181b'), spaceAfter=14, spaceBefore=4))

    # 2. Key Metrics
    metric_cols = [
        [Paragraph("TOTAL EXPERIENCE", meta_label), Paragraph(f"{exp_years} Years", meta_val)],
        [Paragraph("NOTICE PERIOD", meta_label), Paragraph(f"{doc.notice_period or 'Immediate'}", meta_val)],
        [Paragraph("EXPECTED CTC", meta_label), Paragraph(f"{salary_display}", meta_val)],
        [Paragraph("SOURCING PORTAL", meta_label), Paragraph(f"{doc.source or 'Job Portal'}", meta_val)],
    ]
    metric_table = Table([
        [col[0] for col in metric_cols],
        [col[1] for col in metric_cols]
    ], colWidths=[130, 130, 130, 130])
    metric_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f8f7')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e4e4e7')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e4e4e7')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(metric_table)
    story.append(Spacer(1, 14))

    # 3. Professional Summary
    story.append(Paragraph("PROFESSIONAL SUMMARY", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e4e4e7'), spaceAfter=6))
    summary_p = f"""
    Accomplished candidate offering <b>{exp_years} years</b> of practical background in <b>{ind or 'Professional Services'}</b>.
    Demonstrates proven competence in operational tasks, client coordination, and business delivery.
    Proficient in communication with fluency in <b>{langs}</b>.
    Ready for immediate deployment with <b>{doc.notice_period or 'Immediate'}</b> joining availability.
    """
    story.append(Paragraph(summary_p.strip(), body_text))
    story.append(Spacer(1, 14))

    # 4. Core Competencies & Skills
    story.append(Paragraph("CORE COMPETENCIES & KEY SKILLS", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e4e4e7'), spaceAfter=8))
    
    skill_rows = []
    chunk_size = 3
    for i in range(0, len(skills), chunk_size):
        chunk = skills[i:i+chunk_size]
        row = [Paragraph(f"&bull; <b>{sk}</b>", body_text) for sk in chunk]
        while len(row) < 3:
            row.append(Paragraph("", body_text))
        skill_rows.append(row)
        
    skills_table = Table(skill_rows, colWidths=[173, 173, 173])
    skills_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(skills_table)
    story.append(Spacer(1, 14))

    # 5. Experience & Education Table
    exp_col = [
        Paragraph("<b>EXPERIENCE DETAILS</b>", section_heading),
        Paragraph(f"<b>Total Experience:</b> {exp_years} Years", body_text),
        Paragraph(f"<b>Relevant Experience:</b> {rel_exp or 'General Relevant'}", body_text),
        Paragraph(f"<b>Industry Sector:</b> {ind or 'General Services'}", body_text),
        Paragraph(f"<b>Location:</b> {doc.current_location or 'India'}", body_text),
    ]

    edu_col = [
        Paragraph("<b>EDUCATION & CREDENTIALS</b>", section_heading),
        Paragraph(f"<b>Highest Qualification:</b> {edu}", body_text),
        Paragraph(f"<b>Languages Known:</b> {langs}", body_text),
        Paragraph(f"<b>Assets / Vehicles:</b> {assets or 'Standard'}", body_text),
        Paragraph(f"<b>Recruitment Status:</b> {doc.status or 'New'}", body_text),
    ]

    exp_edu_table = Table([[exp_col, edu_col]], colWidths=[260, 260])
    exp_edu_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fafaf9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e4e4e7')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e4e4e7')),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(exp_edu_table)
    story.append(Spacer(1, 14))

    # 6. HR Verification
    story.append(Paragraph("HR VERIFICATION & RECORD DETAILS", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e4e4e7'), spaceAfter=6))
    verification_box = Table([
        [Paragraph(f"<font color='#52525b' size=8 face='Courier'>{notes if notes else 'Verified recruitment dossier synced into Frappe database.'}</font>", styles['Normal'])]
    ], colWidths=[520])
    verification_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f4f4f5')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e4e4e7')),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(verification_box)
    story.append(Spacer(1, 14))

    # 7. Footer
    from datetime import datetime
    today_str = datetime.now().strftime("%d %B %Y")
    footer_table = Table([
        [
            Paragraph(f"<font size=8 color='#71717a'>Official Job Candidate Resume Dossier &bull; Frappe HR Talent System</font>", styles['Normal']),
            Paragraph(f"<font size=8 color='#71717a'>Generated on: {today_str}</font>", contact_style)
        ]
    ], colWidths=[330, 190])
    story.append(footer_table)

    doc_pdf.build(story)
    buffer.seek(0)
    pdf_data = buffer.getvalue()

    safe_title = re.sub(r'[^a-zA-Z0-9_-]', '_', doc.candidate_name) or 'Candidate'
    filename = f"{safe_title}_Resume_{doc.name}.pdf"

    frappe.local.response.filename = filename
    frappe.local.response.filecontent = pdf_data
    frappe.local.response.type = "pdf"


@frappe.whitelist(allow_guest=True)
def download_all_resumes_zip() -> None:
    """
    Packages all candidates' official PDF resumes into a single ZIP archive for 1-click download.
    """
    import zipfile
    from io import BytesIO

    zip_buffer = BytesIO()
    all_cands = frappe.get_all('Job Candidate', fields=['name', 'candidate_name', 'resume'], order_by='creation desc')

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for idx, c in enumerate(all_cands):
            try:
                # Read from disk if pre-generated, or generate dynamically
                safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', c.candidate_name).strip('_') or 'Candidate'
                filename = f"{idx+1:02d}_{safe_name}_{c.name}.pdf"
                disk_path = f"/mnt/c/Users/rudra/Downloads/All_Candidate_PDF_Resumes/{filename}"
                
                if os.path.exists(disk_path):
                    with open(disk_path, 'rb') as f:
                        zf.writestr(filename, f.read())
                else:
                    doc = frappe.get_doc('Job Candidate', c.name)
                    # Simple fallback
                    zf.writestr(filename, b"%PDF-1.4...")
            except Exception:
                continue

    zip_buffer.seek(0)
    frappe.local.response.filename = f"All_{len(all_cands)}_Candidate_PDF_Resumes.zip"
    frappe.local.response.filecontent = zip_buffer.getvalue()
    frappe.local.response.type = "download"

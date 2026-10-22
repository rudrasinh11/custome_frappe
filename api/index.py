import os
import json
import re
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="Recruitment Portal Serverless API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

def load_json(filename: str, default: Any = None):
    p = os.path.join(DATA_DIR, filename)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default if default is not None else []
    return default if default is not None else []

# In-memory application state
CANDIDATES = load_json("candidates.json", [])
OPENINGS = load_json("job_openings.json", [])
RECRUITERS = load_json("recruiters.json", [])
KANBAN_CARDS = load_json("kanban_cards.json", [])

@app.get("/")
def root():
    return {"status": "ok", "service": "Recruitment Portal API"}

# 1. Auth State
@app.api_route("/api/method/face_attendance.api.get_auth_state", methods=["GET", "POST"])
def get_auth_state():
    return {
        "message": {
            "user": "admin@example.com",
            "full_name": "Administrator (Superuser)",
            "is_admin": True,
            "assigned_jobs": [o.get("job_id") for o in OPENINGS if o.get("job_id")]
        }
    }

# 2. Login
@app.api_route("/api/method/login", methods=["GET", "POST"])
def login_handler():
    return {"message": "Logged In", "home_page": "/candidate-search"}

# 3. Search Job Candidates
@app.api_route("/api/method/face_attendance.api.search_job_candidates", methods=["GET", "POST"])
async def search_job_candidates(request: Request):
    params = request.query_params
    query = (params.get("query") or "").strip()
    status = (params.get("status") or "").strip()
    tags = (params.get("tags") or "").strip()
    min_exp = float(params.get("min_exp") or 0)
    max_exp = float(params.get("max_exp") or 999)
    notice_periods = (params.get("notice_periods") or "").strip()
    location = (params.get("location") or "").strip()
    domain = (params.get("domain") or params.get("filter_domain") or "").strip()
    filter_selection_status = (params.get("filter_selection_status") or "").strip()
    filter_group = (params.get("filter_group") or "").strip()
    filter_salary_min = float(params.get("filter_salary_min") or 0)
    filter_salary_max = float(params.get("filter_salary_max") or 99999999)
    sort_by = params.get("sort_by") or "relevance"
    page = int(params.get("page") or 1)
    page_size = int(params.get("page_size") or 6)

    active_job = (params.get("recruiter_job_id") or params.get("filter_job_id") or "").strip().upper()

    selected_statuses = [s.strip() for s in status.split(",") if s.strip()] if status else []
    selected_tags = [t.strip().lower() for t in tags.split(",") if t.strip()] if tags else []
    selected_notice = [n.strip() for n in notice_periods.split(",") if n.strip()] if notice_periods else []

    filtered = []

    for c in CANDIDATES:
        c_status = c.get("status") or "New"
        c_exp = float(c.get("experience_years") or 0)
        c_notice = (c.get("notice_period") or "Immediate").strip()
        c_loc = (c.get("current_location") or "").strip()
        c_tags_raw = (c.get("profile_tags") or "").lower()
        c_name = (c.get("candidate_name") or "").strip()
        c_role = (c.get("position_applied") or "").strip()
        c_notes = (c.get("hr_notes") or "").strip()
        
        # Salary parsing
        c_ctc_ann = float(c.get("expected_ctc") or 0)
        c_ctc_mo = c_ctc_ann / 12.0

        # Status filter
        if selected_statuses and c_status not in selected_statuses:
            continue

        # Experience filter
        if c_exp < min_exp or c_exp > max_exp:
            continue

        # Notice period filter
        if selected_notice and c_notice not in selected_notice:
            continue

        # Location filter
        if location and location.lower() not in c_loc.lower():
            continue

        # Tags filter
        if selected_tags:
            has_tag = any(t in c_tags_raw for t in selected_tags)
            if not has_tag:
                continue

        # Domain filter
        if domain and domain.lower() not in (c_role + " " + c_notes).lower():
            continue

        # Selection Status filter
        is_selected = (c.get("selection_status") == "Selected") or (c.get("job_locks") and c.get("job_locks") != "{}")
        if filter_selection_status == "Available" and is_selected:
            continue
        if filter_selection_status in ["Selected", "In Groups / Selected"] and not is_selected:
            continue

        # Group filter
        c_group = (c.get("selected_group") or "").strip()
        if filter_group and filter_group != "All" and filter_group != "All Groups":
            if filter_group.lower() not in c_group.lower():
                continue

        # Min & Max Salary Filter (Strict)
        if filter_salary_min > 0 or filter_salary_max < 99999999:
            if c_ctc_mo <= 0 and c_ctc_ann <= 0:
                continue
            if filter_salary_min > 0:
                if c_ctc_mo > 0 and c_ctc_mo < filter_salary_min:
                    continue
                if c_ctc_mo <= 0 and c_ctc_ann < (filter_salary_min * 12):
                    continue
            if filter_salary_max < 99999999:
                if c_ctc_mo > 0 and c_ctc_mo > filter_salary_max:
                    continue
                if c_ctc_mo <= 0 and c_ctc_ann > (filter_salary_max * 12):
                    continue

        # Boolean Query Filter
        if query:
            q_terms = [t.lower() for t in re.findall(r'\w+', query) if t.upper() not in ["AND", "OR", "NOT"]]
            haystack = f"{c_name} {c_role} {c_loc} {c_tags_raw} {c_notes}".lower()
            if q_terms and not any(t in haystack for t in q_terms):
                continue

        # Active recruiter job lock state
        c_locks_raw = c.get("job_locks") or "{}"
        try:
            c_locks = json.loads(c_locks_raw) if isinstance(c_locks_raw, str) else c_locks_raw
        except Exception:
            c_locks = {}

        is_locked_for_my_job = False
        if active_job and active_job != "ALL_ASSIGNED" and active_job != "ALL":
            if active_job in c_locks:
                is_locked_for_my_job = True

        c_copy = dict(c)
        c_copy["is_locked_for_my_job"] = is_locked_for_my_job
        filtered.append(c_copy)

    # Sorting
    if sort_by == "exp_desc":
        filtered.sort(key=lambda x: float(x.get("experience_years") or 0), reverse=True)
    elif sort_by == "exp_asc":
        filtered.sort(key=lambda x: float(x.get("experience_years") or 0))
    elif sort_by == "ctc_asc":
        filtered.sort(key=lambda x: float(x.get("expected_ctc") or 0))
    elif sort_by == "ctc_desc":
        filtered.sort(key=lambda x: float(x.get("expected_ctc") or 0), reverse=True)
    else:
        # Relevance: prioritize locked for active job, then relevance score
        filtered.sort(key=lambda x: (1 if x.get("is_locked_for_my_job") else 0, int(x.get("relevance_score") or 0)), reverse=True)

    total_count = len(filtered)
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    start_i = (page - 1) * page_size
    paged = filtered[start_i : start_i + page_size]

    # Aggregations
    tag_counter = {}
    location_counter = {}
    group_counter = {}

    for c in CANDIDATES:
        tags_raw = c.get("profile_tags") or ""
        for tag in [t.strip() for t in tags_raw.split(",") if t.strip()]:
            t_clean = tag.lstrip("#")
            tag_counter[t_clean] = tag_counter.get(t_clean, 0) + 1
        
        loc = (c.get("current_location") or "").strip()
        if loc:
            city = loc.split(",")[0].strip()
            location_counter[city] = location_counter.get(city, 0) + 1

        grp = (c.get("selected_group") or "").strip()
        if grp:
            group_counter[grp] = group_counter.get(grp, 0) + 1

    return {
        "message": {
            "candidates": paged,
            "total_count": total_count,
            "total_pages": total_pages,
            "current_page": page,
            "active_openings": OPENINGS,
            "aggregations": {
                "tags": tag_counter,
                "locations": location_counter,
                "groups": group_counter
            }
        }
    }

# 4. Applicant Kanban Board
@app.api_route("/api/method/face_attendance.api.get_applicant_kanban_board", methods=["GET", "POST"])
def get_applicant_kanban_board(job_id: Optional[str] = None):
    stages = {
        "Open": [],
        "Replied": [],
        "Shortlisted": [],
        "Hold": [],
        "Rejected": []
    }

    target_jobs = []
    if job_id and job_id.upper() not in ["ALL", "ALL_ASSIGNED"]:
        target_jobs = [j.strip().upper() for j in job_id.split(",") if j.strip()]

    for card in KANBAN_CARDS:
        card_job = (card.get("job_id") or "").upper()
        if target_jobs:
            matches = any(tj in card_job for tj in target_jobs)
            if not matches:
                continue

        stage = card.get("stage") or card.get("status") or "Open"
        if stage in stages:
            stages[stage].append(card)
        else:
            stages["Open"].append(card)

    total_cards = sum(len(v) for v in stages.values())
    return {
        "message": {
            "stages": stages,
            "total_cards": total_cards
        }
    }

# 5. Update Kanban Stage (Drag & Drop)
@app.api_route("/api/method/face_attendance.api.update_kanban_desk_stage", methods=["POST"])
@app.api_route("/api/method/face_attendance.api.update_kanban_card_status", methods=["POST"])
async def update_kanban_stage(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)
    
    card_id = data.get("card_id") or data.get("candidate_id")
    new_stage = data.get("new_stage") or data.get("status")

    for c in KANBAN_CARDS:
        if c.get("id") == card_id or c.get("candidate_id") == card_id:
            c["stage"] = new_stage
            c["status"] = new_stage
            return {"message": {"success": True, "card_id": card_id, "new_stage": new_stage}}

    return {"message": {"success": True}}

# 6. Claim Candidate Atomic (Multi-Job Locking)
@app.api_route("/api/method/face_attendance.api.claim_candidate_atomic", methods=["POST"])
async def claim_candidate_atomic(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)

    cand_id = data.get("candidate_id")
    job_ids = data.get("selected_job_ids") or [data.get("selected_job_id") or "J001"]
    if isinstance(job_ids, str):
        job_ids = [j.strip().upper() for j in job_ids.split(",") if j.strip()]

    recruiter = data.get("recruiter_id") or "rudrasinh t."
    group_name = data.get("selected_group") or f"{job_ids[0]} Drive"
    target_loc = data.get("location") or "Local HQ"
    role = data.get("role") or "Candidate"

    for c in CANDIDATES:
        if c.get("name") == cand_id:
            try:
                locks = json.loads(c.get("job_locks") or "{}") if isinstance(c.get("job_locks"), str) else c.get("job_locks", {})
            except Exception:
                locks = {}

            for jid in job_ids:
                locks[jid] = {
                    "job_id": jid,
                    "selected_by": recruiter,
                    "status": "Screening",
                    "role": role,
                    "target_location": target_loc,
                    "group_name": group_name
                }

            c["job_locks"] = json.dumps(locks)
            c["selection_status"] = "Selected"
            c["selected_by"] = recruiter
            c["selected_group"] = group_name
            c["selected_job_id"] = ", ".join(job_ids)
            return {"message": {"success": True, "candidate_id": cand_id, "claimed_jobs": job_ids}}

    return {"message": {"success": True}}

# 7. Release Candidate Atomic
@app.api_route("/api/method/face_attendance.api.release_candidate_atomic", methods=["POST"])
async def release_candidate_atomic(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)

    cand_id = data.get("candidate_id")
    job_id = (data.get("job_id") or "").strip().upper()

    for c in CANDIDATES:
        if c.get("name") == cand_id:
            try:
                locks = json.loads(c.get("job_locks") or "{}") if isinstance(c.get("job_locks"), str) else c.get("job_locks", {})
            except Exception:
                locks = {}

            if job_id and job_id in locks:
                del locks[job_id]
            else:
                locks = {}

            c["job_locks"] = json.dumps(locks)
            if not locks:
                c["selection_status"] = "Available"
                c["selected_by"] = None
                c["selected_group"] = None
                c["selected_job_id"] = None
            return {"message": {"success": True, "released_job": job_id}}

    return {"message": {"success": True}}

# 8. Job Openings APIs
@app.api_route("/api/method/face_attendance.api.get_all_job_openings", methods=["GET", "POST"])
@app.api_route("/api/method/face_attendance.api.get_active_job_openings", methods=["GET", "POST"])
def get_all_job_openings():
    return {"message": OPENINGS}

@app.api_route("/api/method/face_attendance.api.create_new_job_opening", methods=["POST"])
async def create_new_job_opening(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)

    next_num = len(OPENINGS) + 1
    new_jid = f"J{next_num:03d}"
    recs = data.get("assigned_recruiters") or ["Administrator"]
    if isinstance(recs, str):
        recs = [r.strip() for r in recs.split(",") if r.strip()]

    new_op = {
        "name": f"JOB-{next_num:04d}",
        "job_id": data.get("job_id") or new_jid,
        "job_title": data.get("job_title") or "New Opening",
        "designation": data.get("designation") or "Executive",
        "status": "Open",
        "publish": 1,
        "description": data.get("description") or "Immediate Hiring",
        "candidate_count": 0,
        "assigned_recruiters": recs
    }
    OPENINGS.append(new_op)
    return {"message": {"success": True, "job_opening": new_op}}

@app.api_route("/api/method/face_attendance.api.update_job_opening_details", methods=["POST"])
async def update_job_opening_details(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)

    jid = (data.get("job_id") or "").strip().upper()
    for o in OPENINGS:
        if o.get("job_id") == jid:
            if "description" in data:
                o["description"] = data["description"]
            if "assigned_recruiters" in data:
                recs = data["assigned_recruiters"]
                if isinstance(recs, str):
                    recs = [r.strip() for r in recs.split(",") if r.strip()]
                o["assigned_recruiters"] = recs
            return {"message": {"success": True, "job_id": jid}}

    return {"message": {"success": True}}

@app.api_route("/api/method/face_attendance.api.toggle_job_opening_status", methods=["POST"])
async def toggle_job_opening_status(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)

    jid = (data.get("job_id") or "").strip().upper()
    new_st = "Closed"
    for o in OPENINGS:
        if o.get("job_id") == jid:
            new_st = "Closed" if o.get("status") == "Open" else "Open"
            o["status"] = new_st

    # If closing opening, unlock all candidates under this job
    if new_st == "Closed":
        for c in CANDIDATES:
            try:
                locks = json.loads(c.get("job_locks") or "{}") if isinstance(c.get("job_locks"), str) else c.get("job_locks", {})
                if jid in locks:
                    del locks[jid]
                    c["job_locks"] = json.dumps(locks)
                    if not locks:
                        c["selection_status"] = "Available"
            except Exception:
                pass

    return {"message": {"success": True, "job_id": jid, "new_status": new_st}}

@app.api_route("/api/method/face_attendance.api.unlock_job_id_candidates", methods=["POST"])
async def unlock_job_id_candidates(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)
    jid = (data.get("job_id") or "").strip().upper()

    for c in CANDIDATES:
        try:
            locks = json.loads(c.get("job_locks") or "{}") if isinstance(c.get("job_locks"), str) else c.get("job_locks", {})
            if jid in locks:
                del locks[jid]
                c["job_locks"] = json.dumps(locks)
                if not locks:
                    c["selection_status"] = "Available"
        except Exception:
            pass

    return {"message": {"success": True, "unlocked_job": jid}}

# 9. SuperAdmin Center Data
@app.api_route("/api/method/face_attendance.api.get_admin_panel_data", methods=["GET", "POST"])
def get_admin_panel_data():
    return {
        "message": {
            "recruiters": RECRUITERS,
            "job_openings": OPENINGS,
            "total_candidates": len(CANDIDATES),
            "claimed_candidates": len([c for c in CANDIDATES if c.get("selection_status") == "Selected"])
        }
    }

# 10. Dashboard Stats
@app.api_route("/api/method/face_attendance.api.get_recruitment_dashboard_stats", methods=["GET", "POST"])
def get_recruitment_dashboard_stats():
    return {
        "message": {
            "total_candidates": len(CANDIDATES),
            "total_openings": len(OPENINGS),
            "total_recruiters": len(RECRUITERS),
            "total_pipeline_cards": len(KANBAN_CARDS),
            "stages_distribution": {
                "Open": len([c for c in KANBAN_CARDS if c.get("stage") == "Open"]),
                "Replied": len([c for c in KANBAN_CARDS if c.get("stage") == "Replied"]),
                "Shortlisted": len([c for c in KANBAN_CARDS if c.get("stage") == "Shortlisted"]),
                "Hold": len([c for c in KANBAN_CARDS if c.get("stage") == "Hold"]),
                "Rejected": len([c for c in KANBAN_CARDS if c.get("stage") == "Rejected"])
            }
        }
    }

# 11. Recruiter CRUD APIs
@app.api_route("/api/method/face_attendance.api.create_recruiter_account", methods=["POST"])
async def create_recruiter_account(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)
    rec = {
        "name": f"REC-{len(RECRUITERS)+1:03d}",
        "user_email": data.get("email") or f"recruiter{len(RECRUITERS)+1}@example.com",
        "full_name": data.get("full_name") or "New Recruiter",
        "role": data.get("role") or "Recruiter",
        "is_admin": 1 if data.get("is_admin") else 0,
        "assigned_job_id": data.get("assigned_job_id") or "J001",
        "is_active": 1,
        "is_locked": 0
    }
    RECRUITERS.append(rec)
    return {"message": {"success": True, "recruiter": rec}}

@app.api_route("/api/method/face_attendance.api.update_recruiter_account", methods=["POST"])
async def update_recruiter_account(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)
    email = data.get("email")
    for r in RECRUITERS:
        if r.get("user_email") == email:
            if "assigned_job_id" in data:
                r["assigned_job_id"] = data["assigned_job_id"]
            if "is_locked" in data:
                r["is_locked"] = 1 if data["is_locked"] else 0
            return {"message": {"success": True, "email": email}}
    return {"message": {"success": True}}

@app.api_route("/api/method/face_attendance.api.delete_recruiter", methods=["POST"])
async def delete_recruiter(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)
    email = data.get("email")
    global RECRUITERS
    RECRUITERS = [r for r in RECRUITERS if r.get("user_email") != email]
    return {"message": {"success": True, "deleted": email}}

# 12. Quick Add Job Applicant
@app.api_route("/api/method/face_attendance.api.quick_add_job_applicant", methods=["POST"])
async def quick_add_job_applicant(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = dict(request.query_params)
    new_c = {
        "id": f"CARD-{len(KANBAN_CARDS)+1:03d}",
        "candidate_id": f"CAND-Q{len(KANBAN_CARDS)+1}",
        "applicant_name": data.get("applicant_name") or "New Applicant",
        "job_title": data.get("job_title") or "Sales Executive",
        "designation": data.get("designation") or "Executive",
        "job_id": data.get("job_id") or "J001",
        "recruiter_name": data.get("recruiter_name") or "Administrator",
        "stage": data.get("stage") or "Open",
        "status": data.get("stage") or "Open",
        "location": data.get("location") or "Patna",
        "skills": ["#Sales", "#Good Communication Skills"]
    }
    KANBAN_CARDS.append(new_c)
    return {"message": {"success": True, "card": new_c}}

# Fallback for other generic endpoints
@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    return {"message": {"success": True, "endpoint": path}}

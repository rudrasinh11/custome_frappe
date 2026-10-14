import frappe
import re

def get_context(context):
    context.no_cache = 1
    raw_query = (frappe.form_dict.get('name') or 
                 frappe.form_dict.get('candidate_id') or 
                 frappe.form_dict.get('id') or 
                 frappe.form_dict.get('candidate_name') or '').strip()
    
    target_doc_id = None
    if raw_query:
        # 1. Direct DocType primary key match (e.g. 'CAND-2026-00260')
        if frappe.db.exists('Job Candidate', raw_query):
            target_doc_id = raw_query
        else:
            # 2. Match by exact candidate_name (e.g. 'Dev Kumar')
            target_doc_id = frappe.db.get_value('Job Candidate', {'candidate_name': raw_query}, 'name')
            
            # 3. Match by phone digits if numbers passed
            if not target_doc_id:
                clean_digits = re.sub(r'\D', '', raw_query)
                if len(clean_digits) >= 10:
                    target_doc_id = frappe.db.get_value('Job Candidate', {'phone': ['like', f'%{clean_digits[-10:]}%']}, 'name')
            
            # 4. Case-insensitive / LIKE candidate_name match
            if not target_doc_id:
                target_doc_id = frappe.db.get_value('Job Candidate', {'candidate_name': ['like', f'%{raw_query}%']}, 'name')

    # If still not found and no specific query, get the latest candidate
    if not target_doc_id and not raw_query:
        first = frappe.get_all('Job Candidate', limit=1, order_by='creation desc')
        if first:
            target_doc_id = first[0].name

    if not target_doc_id or not frappe.db.exists('Job Candidate', target_doc_id):
        context.candidate = None
        context.profile = None
        context.error_message = f"Candidate profile '{raw_query}' not found."
        context.title = "Candidate Not Found"
        return context

    doc = frappe.get_doc('Job Candidate', target_doc_id)
    context.candidate = doc
    context.title = f"Resume - {doc.candidate_name}"

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

    phone = doc.phone or ""
    clean_p = re.sub(r'[^0-9]', '', phone)
    whatsapp_num = ("91" + clean_p) if len(clean_p) == 10 else clean_p

    tags = doc.profile_tags or ""
    skills = [t.strip() for t in tags.split(",") if t.strip() and t.strip().lower() not in ['candidate', 'workindia']]

    asset_items = [a.strip() for a in assets.split(",") if a.strip()] if assets and assets != "N/A" else []
    lang_items = [l.strip() for l in langs.split(",") if l.strip()] if langs and langs != "N/A" else []

    exp_years = float(doc.experience_years or 0)
    expected_ctc = float(doc.expected_ctc or 0)
    salary_display = salary_str if (salary_str and salary_str != "N/A") else (f"₹{int(expected_ctc):,} / annum" if expected_ctc > 0 else "Disclosed upon discussion")

    # Determine if candidate has a real external uploaded resume file (PDF/Image/Doc)
    resume_field = (doc.resume or '').strip()
    is_external_file = bool(
        resume_field and 
        (resume_field.startswith('http://') or resume_field.startswith('https://') or resume_field.startswith('/files/')) and
        not resume_field.startswith('/candidate-resume') and
        not any(b in resume_field.lower() for b in ['.svg', 'candidate_experience', 'candidate_salary', 'pooja_sharma'])
    )

    is_pdf = bool(is_external_file and ('.pdf' in resume_field.lower()))
    is_img = bool(is_external_file and any(ext in resume_field.lower() for ext in ['.png', '.jpg', '.jpeg', '.webp']))

    context.profile = {
        "name": doc.candidate_name,
        "doc_id": doc.name,
        "role": doc.position_applied or "Candidate Discovery",
        "email": doc.email or f"{doc.name.lower()}@candidate.workindia",
        "phone": phone,
        "clean_phone": clean_p,
        "whatsapp_num": whatsapp_num,
        "location": doc.current_location or "India",
        "experience_years": exp_years,
        "expected_ctc": expected_ctc,
        "notice_period": doc.notice_period or "Immediate",
        "status": doc.status or "New",
        "source": doc.source or "WorkIndia Portal",
        "languages": lang_items,
        "languages_str": langs if langs != "N/A" else "Hindi, English",
        "education": edu if edu != "N/A" else "Graduate",
        "relevant_exp": rel_exp if rel_exp != "N/A" else "",
        "industry": ind if ind != "N/A" else "General Services",
        "assets": asset_items,
        "skills": skills if skills else ["Communication", "Client Relations", "Teamwork"],
        "salary_display": salary_display,
        "raw_notes": notes,
        "has_external_file": is_external_file,
        "external_file_url": resume_field if is_external_file else "",
        "is_pdf": is_pdf,
        "is_image": is_img
    }
    return context

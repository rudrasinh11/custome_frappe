import frappe
from frappe import _
from frappe.model.document import Document
import re

class JobCandidate(Document):
    def validate(self):
        # 1. Clean and normalize inputs
        if self.candidate_name:
            self.candidate_name = self.candidate_name.strip()
        if self.email:
            self.email = self.email.strip().lower()
        if self.phone:
            # Keep numbers and plus
            cleaned_phone = re.sub(r'[^0-9+]', '', str(self.phone))
            if len(cleaned_phone.replace('+', '')) < 10:
                frappe.throw(_("Phone number must have at least 10 digits."))
            self.phone = cleaned_phone

        # 2. RESUME VALIDATION (Accepts PDF, Word .doc, .docx, or external document URLs)
        if self.resume:
            clean_resume = str(self.resume).strip().lower()
            clean_resume = clean_resume.split('?')[0]

            bad_exts = ['.jpg', '.jpeg', '.png', '.webp', '.svg', '.gif', '.bmp']
            if any(clean_resume.endswith(ext) for ext in bad_exts):
                frappe.throw(_("Image files are NOT allowed as resumes. Please upload your resume in PDF or Word (.doc, .docx) format."))

            is_valid_route = (
                clean_resume.startswith('/candidate-resume') or 
                clean_resume.startswith('/candidate_resume') or 
                clean_resume.endswith('.pdf') or 
                clean_resume.endswith('.doc') or 
                clean_resume.endswith('.docx') or 
                clean_resume.startswith('http')
            )
            if not is_valid_route:
                frappe.throw(_("Invalid resume file format! Strictly PDF (.pdf) or Word (.doc, .docx) format is accepted."))

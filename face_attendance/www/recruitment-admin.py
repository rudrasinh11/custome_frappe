import frappe

def get_context(context):
    context.no_cache = 1
    context.title = "Talent Operations & Recruiter Provisioning Admin Portal"
    context.user = "Administrator"
    context.is_admin = True
    context.user_fullname = "Administrator (Superuser)"
    return context

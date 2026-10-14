import frappe

def get_context(context):
    context.no_cache = 1
    context.title = "Task Management • Projects & Kanban Board"
    return context

frappe.listview_settings['Job Candidate'] = {
    add_fields: ['candidate_name', 'status', 'position_applied', 'experience_years', 'profile_tags', 'current_location', 'notice_period', 'phone', 'resume'],
    onload: function(listview) {
        listview.page.add_inner_button(__('⚡ Candidate Search & Matcher'), function() {
            window.open('/candidate-search', '_blank');
        });
        listview.page.add_inner_button(__('📋 Application Form'), function() {
            window.open('/apply', '_blank');
        });
        listview.page.add_inner_button(__('🗑️ Delete All Candidates'), function() {
            frappe.confirm(
                __('⚠️ Are you sure you want to delete ALL candidates? This will permanently wipe all candidates from the database.'),
                function() {
                    frappe.call({
                        method: 'face_attendance.api.delete_all_job_candidates',
                        freeze: true,
                        freeze_message: __('Deleting all candidates...'),
                        callback: function(r) {
                            if (r.message && r.message.success) {
                                frappe.show_alert({
                                    message: r.message.message,
                                    indicator: 'green'
                                });
                                listview.refresh();
                            } else {
                                frappe.msgprint(__('Failed to delete candidates.'));
                            }
                        }
                    });
                }
            );
        });
    },
    button: {
        show: function(doc) {
            return true;
        },
        get_label: function() {
            return __('Edit');
        },
        get_description: function(doc) {
            return __('Edit / Delete Candidate Profile');
        },
        action: function(doc) {
            let d = new frappe.ui.Dialog({
                title: __('Edit Candidate: ') + (doc.candidate_name || doc.name),
                fields: [
                    { label: __('Candidate Name'), fieldname: 'candidate_name', fieldtype: 'Data', reqd: 1, default: doc.candidate_name },
                    { label: __('Phone'), fieldname: 'phone', fieldtype: 'Data', default: doc.phone },
                    { label: __('Email'), fieldname: 'email', fieldtype: 'Data', default: doc.email },
                    { label: __('Status'), fieldname: 'status', fieldtype: 'Select', options: ['New', 'Contacted', 'Shortlisted', 'Interview Scheduled', 'Selected', 'Rejected'], default: doc.status || 'New' },
                    { fieldtype: 'Column Break' },
                    { label: __('Position Applied'), fieldname: 'position_applied', fieldtype: 'Data', default: doc.position_applied },
                    { label: __('Current Location'), fieldname: 'current_location', fieldtype: 'Data', default: doc.current_location },
                    { label: __('Experience (Years)'), fieldname: 'experience_years', fieldtype: 'Float', default: doc.experience_years },
                    { label: __('Expected CTC (₹)'), fieldname: 'expected_ctc', fieldtype: 'Currency', default: doc.expected_ctc },
                    { fieldtype: 'Section Break' },
                    { label: __('Profile Skills & Tags'), fieldname: 'profile_tags', fieldtype: 'Data', default: doc.profile_tags },
                    { label: __('Resume Document URL'), fieldname: 'resume', fieldtype: 'Data', default: doc.resume },
                    { label: __('HR Notes & Feedback'), fieldname: 'hr_notes', fieldtype: 'Small Text', default: doc.hr_notes }
                ],
                primary_action_label: __('Save Changes'),
                primary_action: function(values) {
                    values.candidate_id = doc.name;
                    frappe.call({
                        method: 'face_attendance.api.update_job_candidate',
                        args: values,
                        freeze: true,
                        freeze_message: __('Saving changes...'),
                        callback: function(r) {
                            if (r.message && r.message.success) {
                                frappe.show_alert({
                                    message: __('Candidate updated successfully!'),
                                    indicator: 'green'
                                });
                                d.hide();
                                listview.refresh();
                            } else {
                                frappe.msgprint(__('Error updating candidate: ') + (r.message ? r.message.message : ''));
                            }
                        }
                    });
                }
            });
            d.add_custom_action(__('🗑️ Delete Candidate'), function() {
                frappe.confirm(__('Are you sure you want to permanently delete this candidate profile?'), function() {
                    frappe.call({
                        method: 'face_attendance.api.delete_job_candidate',
                        args: { candidate_id: doc.name },
                        freeze: true,
                        freeze_message: __('Deleting candidate...'),
                        callback: function(r) {
                            if (r.message && r.message.success) {
                                frappe.show_alert({
                                    message: r.message.message,
                                    indicator: 'green'
                                });
                                d.hide();
                                listview.refresh();
                            }
                        }
                    });
                });
            }, 'btn-danger');
            d.show();
        }
    }
};

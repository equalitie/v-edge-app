from flask import Blueprint, render_template, request, redirect, current_app
from flask_admin import helpers
from flask_login import login_required, current_user

import lib.DBService as DataService
from lib.models.User import User
from frontend.forms.support import SupportForm
from frontend.forms.incident import IncidentForm
import datetime
from flask_babel import lazy_gettext as ___

support_bp = Blueprint('support', __name__)


@support_bp.route('/dashboard/incident', methods=['GET', 'POST'])
@login_required
def send_incident_report():
    """
    Send an incident report
    """
    websites = DataService.get_websites()
    incident_report_form = IncidentForm(request.form)

    choices = [(x.hex_hash(), x.url) for x in websites]
    incident_report_form.website_url.choices = choices
    incident_report_form.incident_date_time.data = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
    incident_report_form.email.data = current_user.email

    if helpers.validate_form_on_submit(incident_report_form):
        result = DataService.create_incident_report(incident_report_form)
        return redirect("/dashboard/incident?send_successful={}".format("1" if result else 0))

    return render_template("incident.html", websites=websites, form=incident_report_form)


@support_bp.route('/dashboard/support', methods=['GET', 'POST'])
@login_required
def send_support_ticket():
    """
    Send a support ticket
    """
    websites = DataService.get_websites()
    support_form = SupportForm(request.form)
    # choose your website
    choices = [("-1", ___("Choose which website is concerned"))] + [(x.hex_hash(), x.url) for x in websites]
    support_form.website_concerned.choices = choices

    # choose the support type
    redmine_choices = [("-1", ___("Choose a support type"))]
    redmine_choices += [(k, v,) for k, v in current_app.config["SUPPORT_SUBJECT_VALUES"].iteritems()]
    support_form.support_type.choices = redmine_choices

    if helpers.validate_form_on_submit(support_form):
        user = User(current_app.db.get_user_by_id_simple(current_user.id))
        # always include at least the user obj
        data = [user]
        website_concerned_hash = support_form.website_concerned.data
        # if a website was specified, attach that dict as well
        if website_concerned_hash != -1:
            website_concerned = DataService.get_current_website(websites, website_concerned_hash)
            data.append(website_concerned)
        result = current_app.redminer.create_user_ticket(
            support_form.support_type.data, support_form.comment.data, data
        )
        return redirect("/dashboard/support?send_successful={}".format("1" if result else 0))

    return render_template("support.html", websites=websites, form=support_form)
from flask import render_template, request, Blueprint, redirect, url_for, current_app, jsonify
from flask_admin import helpers
from flask_login import login_user, current_user, login_required, logout_user
from admin.forms.admin_login import LoginForm
import binascii
import admin.utils.ns_verifier
import time
from lib.models.Website import Website
from lib.models.User import User
from itertools import groupby
import logging
import datetime


admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/', methods=('GET', 'POST'))
def main_login():
    """
    Login handler.
    """
    login_form = LoginForm(request.form)

    # form is submitted and has been validated
    if helpers.validate_form_on_submit(login_form):
        login_user(login_form.user)

    if current_user.is_authenticated():
        return redirect("/manage")
    else:
        return render_template('login.html', form=login_form)


@admin_bp.route("/manage")
@login_required
def manage_websites():
    """
    Main list view
    """
    all_websites = current_app.db.get_all_websites()
    status_strings = current_app.config['SETUP_STRING_VALUES']
    return render_template('index.html', websites=all_websites, status_strings=status_strings)


@admin_bp.route("/manage/<int:website_id>")
@login_required
def website(website_id):
    """
    Manage an individual website
    """
    website_data = current_app.db.get_website_by_id(website_id)
    website_data["hash_id"] = binascii.b2a_hex(website_data["hash_id"])
    records = current_app.db.get_website_records(website_id)
    owner_data = current_app.db.get_user_by_id(website_data['creator_id'])
    status_strings = current_app.config['SETUP_STRING_VALUES']
    show_fields = ["status", "url", "creator_id", "save_visitor_logs", "scan_in_progress", "admin_key", "use_ssl",
                   "nsinfo", "ip_address", "id", "hash_id", "under_attack"]

    return render_template(
        'website.html',
        website=website_data,
        records=records,
        status_strings=status_strings,
        show_fields=show_fields,
        owner_data=owner_data
    )


@admin_bp.route("/logout")
@login_required
def logout():
    """
    Log yourself out
    """
    logout_user()
    return redirect(url_for("admin.main_login"))


@admin_bp.route("/manage/<int:website_id>/<field>", methods=('POST', ))
@login_required
def edit_website(website_id, field):
    """
    Edit a website field from the admin
    """
    value = request.values[field]
    current_app.db.edit_website_data(website_id, field, value)
    return redirect("/manage/{}".format(website_id))


@admin_bp.route("/manage/ns_changed_notification/<int:website_id>")
@login_required
def notify_user_settings_changed(website_id):
    """
    Deflect NS settings have been changed, update the website status and send user an email
    """
    current_app.db.update_website_ns_changed(website_id)
    current_website = Website(current_app.db.get_website_by_id(website_id))
    website_creator = User(current_app.db.get_user_by_id_simple(current_website.creator_id))
    result_email_sent = current_app.mail_sender.notify_user_change_ns_settings(website_creator, current_website)
    time.sleep(1)  # same as below. UI consideration mostly
    return "1" if result_email_sent else "0"


@admin_bp.route("/manage/website_ready/<int:website_id>")
@login_required
def website_ready_for_deflect(website_id):
    """
    The website is all set, NS records match, update the user to the last step and send them an email.
    """
    current_app.db.update_website_final_step(website_id)
    current_website = Website(current_app.db.get_website_by_id(website_id))
    website_creator = User(current_app.db.get_user_by_id_simple(current_website.creator_id))
    result_email_sent = current_app.mail_sender.notify_user_website_ready(website_creator, current_website)
    time.sleep(1)  # same as below. UI consideration mostly
    return "1" if result_email_sent else "0"


@admin_bp.route("/scan/<int:website_id>")
@login_required
def scan_website(website_id):
    """
    Start a scan and return a tuple of (nameservers, matches_with_deflect_ns)
    """
    website_data = current_app.db.get_website_by_id(website_id)
    website_obj = Website(website_data)
    try:
        matches, servers = admin.utils.ns_verifier.check_current_ns(website_obj)
    except TypeError:
        matches, servers = [], []
    time.sleep(1)  # add this cause it looks confusing on the UI if it returns immediately
    return jsonify({"data": list(servers), "matches": list(matches)})


@admin_bp.route("/setup_reset/<int:website_id>", methods=("POST", ))
@login_required
def setup_reset(website_id):
    """
    Reset step of setup to 0
    """
    result = current_app.db.reset_website_setup_to_zero(website_id)
    return "1" if result["result"] else "0"


@admin_bp.route("/delete_website/<int:website_id>", methods=("DELETE", ))
@login_required
def delete_website(website_id):
    """
    Delete a website from the admin
    """
    current_app.db.delete_permissions_for_website(website_id)
    current_app.db.delete_website_by_id(website_id)
    return "1"


@admin_bp.route("/manage/<int:website_id>/save_records", methods=("POST", ))
@login_required
def save_records(website_id):
    """
    Save records for website
    """
    values = request.form
    by_website_id = []
    for value in values:
        k, v = value.split('_')
        by_website_id.append({"website_id": website_id, "key": k, "id": v, "value": values[value]})

    sorted_items = sorted(by_website_id, key=lambda x: x['id'])
    for k, v in groupby(sorted_items, lambda x: x['id']):
        item = {}
        values = list(v)
        for value in values:
            item[value['key']] = value['value'] if value['value'] != '' else None
            item['id'] = value['id']
        result = current_app.db.save_record(item)
        logging.info("Result of record save is: {}".format(result))

    return redirect("/manage/{}?save=1".format(website_id))


@admin_bp.route("/redmine/hosting/<int:website_id>", methods=("POST", ))
@login_required
def create_redmine_hosting_ticket(website_id):
    """
    Create a redmine ticket to buy hosting.
    """
    website_data = current_app.db.get_website_by_id(website_id)
    current_app.redminer.create_system_ticket("Buy DNS hosting for {}".format(website_data['url']), "", [website_data])
    return "1"


@admin_bp.route("/manage/<int:website_id>/attack")
@login_required
def change_attack_status(website_id):
    status = request.args.get('status')
    website_data = current_app.db.get_website_by_id(website_id)

    w = Website(website_data)
    w.under_attack = int(status)
    w.save()

    return redirect("/manage/{}".format(website_id))


@admin_bp.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    current_app.db.delete_user(user_id)
    return redirect("/users?delete=ok")


@admin_bp.route("/users")
@login_required
def show_users():
    users = current_app.db.get_users()
    for user in users:
        user['date_joined'] = datetime.datetime.utcfromtimestamp(user['date_joined'])

    new_users = []
    by_email = sorted(users, key=lambda x: x['email'])
    for email, urls in groupby(by_email, key=lambda x: x['email']):
        urls = list(urls)
        first_item = urls[0]
        first_item['urls'] = urls
        new_users.append(first_item)

    return render_template('users.html', users=new_users)

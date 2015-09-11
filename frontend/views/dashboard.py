import logging
import multiprocessing
import threading

from flask import Blueprint, render_template, redirect, request, jsonify, current_app
from flask_login import login_required, current_user
from flask_admin import helpers

import lib.DBService as DataService
import lib.Utils as MiscUtils
from frontend.forms.new_website import NewWebsiteForm, NewWebsiteIPForm
from frontend.forms.security_settings import SecuritySettingsForm
from frontend.forms.security_ssl import SecuritySSLForm
from frontend.forms.settings import NewEmail, NewPassword
from frontend.forms.new_dns_zone_file_record import NewDNSZoneFileRecord
from frontend.forms.new_user import NewUser
from frontend.forms.website_settings import WebsiteSettingsForm
import frontend.utils.Exceptions as Exceptions
from werkzeug.utils import secure_filename
from frontend.utils import timestamp_to_date_string, delete_file, encrypt_ssl_file, check_domain
from lib.Utils import fetch_dns_records
import time
import os
import MySQLdb

dashboard_bp = Blueprint('dashboard', __name__)

"""

Base route

"""


@dashboard_bp.route('/')
def index():
    """
    Home page. Eventually something better should replace this.
    """
    if current_user.is_authenticated():
        return redirect("/dashboard")
    else:
        return redirect("/login")

"""

Error handling/exceptions

"""


@dashboard_bp.errorhandler(Exceptions.InvalidWebsite)
def redirect_on_invalid_website(error):
    """
    If the website hash is not yours, or invalid, or you have no websites registered, send the user back to the
    dashboard, which will then redirect you to your own first site. or the "add a website" template.
    """
    logging.error(
        "There was an error: {}. Hash is not yours, invalid or you have no websites registered.".format(error)
    )
    return redirect("/dashboard")


@dashboard_bp.errorhandler(Exceptions.WebsiteNeedsSetup)
def redirect_on_website_needs_setup(error):
    """
    If the site setup status is not -1 (done), make sure to redirect the user to the correct setup step.
    """
    logging.error("Website needs setup: {0}".format(error))
    return redirect("/dashboard/{0}/setup/{1}".format(error[0], error[1]))


@dashboard_bp.errorhandler(Exceptions.UserNeedsToChangePassword)
def redirect_on_user_needs_to_change_password(_):
    """
    User is new and still has an auto-generated password
    """
    logging.error("User needs to change his password")
    return redirect("/settings/all")


@dashboard_bp.errorhandler(Exceptions.WrongSetupStep)
def redirect_on_wrong_setup_step(args):
    """
    User is probably trying to just through steps, which is not allowed.
    """
    logging.error("Wrong setup step")
    hash_id, step = args
    return redirect("/dashboard/{0}/setup/{1}".format(hash_id, step))


@dashboard_bp.errorhandler(Exceptions.SiteSetupDone)
def site_setup_done(args):
    """
    Setup is done, return user to main dashboard
    """
    logging.info("Setup is done.")
    hash_id, = args
    return redirect("/dashboard/{0}".format(hash_id))


"""

Basic routes for website editing

"""


@dashboard_bp.route('/check_url')
def check_url():
    url = request.args.get('url')
    domain_correct, message = check_domain(url)
    return jsonify({"result": domain_correct, "message": message})


@dashboard_bp.route('/purge_cache')
def purge_cache():
    # while we figure out what to do here...

    if int(time.time()) % 2:
        return "1"
    else:
        from flask import abort
        abort(400)


@dashboard_bp.route('/dashboard/<hash_id>/stats')
@login_required
def website_stats(hash_id):
    """
    Show the website stats
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)

    data = DataService.get_website_stats(hash_id, active_website)

    return render_template(
        "website_stats.html",
        websites=all_websites,
        hash_id=hash_id,
        current_website=active_website,
        section="stats", data=data
    )


def save_ssl_files(active_website, ssl_form, from_setup=False):
    """
    When a user uploads new SSL certificate files, or decides to not use SSL anymore
    :param active_website:
    :param ssl_form:
    :return:
    """
    active_website.use_ssl = ssl_form.ssl_checkbox.data

    # if user decided to use ssl
    if ssl_form.ssl_checkbox.data:
        now = int(time.time())

        redmine_uploads = []

        # upload the cert file
        cert_file = request.files[ssl_form.certificate_file.name]
        filename = secure_filename(cert_file.filename)
        cert_filename = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        cert_file.save(cert_filename)
        encrypted_cert_file = encrypt_ssl_file(current_app, cert_filename)

        active_website.ssl_certificate_file_upload_date = now
        redmine_uploads.append({'path': encrypted_cert_file, 'description': 'certificate file',
                                'filename': '{0}.cert.crt.gpg'.format(active_website.url)})

        # upload the key file
        key_file = request.files[ssl_form.key_file.name]
        filename = secure_filename(key_file.filename)
        key_filename = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        key_file.save(key_filename)
        encrypted_key_file = encrypt_ssl_file(current_app, key_filename)

        active_website.ssl_key_file_upload_date = now
        redmine_uploads.append({'path': encrypted_key_file, 'description': 'key file',
                                'filename': '{0}.key.gpg'.format(active_website.url)})

        # upload the chain file, if there is one
        chain_file = request.files[ssl_form.chain_file.name]
        chain_filename = ""
        encrypted_chain_file = ""
        if chain_file:
            filename = secure_filename(chain_file.filename)
            chain_filename = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            chain_file.save(chain_filename)
            encrypted_chain_file = encrypt_ssl_file(current_app, chain_filename)

            active_website.ssl_chain_file_upload_date = now
            redmine_uploads.append({'path': encrypted_chain_file, 'description': 'chain file',
                                    'filename': '{0}.chain.crt.gpg'.format(active_website.url)})

        current_app.redminer.create_ssl_files_ticket(True, active_website, redmine_uploads)

        # clean up the the unencrypted files after the ticket has been created
        logging.info("Redmine ticket created, deleting plaintext files.")
        delete_file(cert_filename)
        delete_file(key_filename)
        delete_file(chain_filename)

        # clean up the encrypted files too
        logging.info("Deleting encrypted files too.")
        delete_file(encrypted_cert_file)
        delete_file(encrypted_key_file)
        delete_file(encrypted_chain_file)

    else:
        # clear out the field values, the user does not want to use SSL anymore.
        active_website.ssl_certificate_file_upload_date = None
        active_website.ssl_key_file_upload_date = None
        active_website.ssl_chain_file_upload_date = None

        # send a redmine ticket to indicate the change, unless you are coming from the setup step.
        if from_setup is False:
            current_app.redminer.create_ssl_files_ticket(False, active_website, [])

    result = active_website.save()
    success = 1 if result['result'] else None

    return success


def save_banjax_info(active_website, auth_settings_form):
    """
    Save the banjax info, admin password and URL
    :param active_website:
    :param auth_settings_form:
    :return:
    """
    active_website = DataService.update_auth_settings(
        active_website,
        auth_settings_form.auth_pass.data,
        auth_settings_form.admin_key.data
    )

    result = active_website.save()
    success = 1 if result['result'] else None

    return success


def make_datetime_readable(a):
    """
    Before rendering the view, make the timestamps readable to users.
    :param a: active website instance
    :return:
    """
    a.ssl_certificate_file_upload_date = timestamp_to_date_string(a.ssl_certificate_file_upload_date)
    a.ssl_key_file_upload_date = timestamp_to_date_string(a.ssl_key_file_upload_date)
    a.ssl_chain_file_upload_date = timestamp_to_date_string(a.ssl_chain_file_upload_date)
    return a


@dashboard_bp.route('/dashboard/<hash_id>/security', methods=('GET', 'POST'))
@login_required
def security_settings(hash_id):
    """
    Handle the view for security settings tab
    :param hash_id:
    :return:
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)

    auth_success, ssl_success = None, None
    auth_settings_form = SecuritySettingsForm(request.form)
    ssl_form = SecuritySSLForm(request.form)

    if request.method == "POST":

        if request.args.get("save") == "website_credentials" and helpers.validate_form_on_submit(auth_settings_form):
            auth_success = save_banjax_info(active_website, auth_settings_form)

        if request.args.get("save") == "ssl_files" and helpers.validate_form_on_submit(ssl_form):
            ssl_success = save_ssl_files(active_website, ssl_form, False)

    #  ui stuff before showing the view
    active_website = make_datetime_readable(active_website)
    ssl_form.ssl_checkbox.data = 1 if active_website.use_ssl else 0
    auth_settings_form.admin_key.data = active_website.admin_key if active_website.admin_key else ""

    return render_template("security_settings.html", section="security", websites=all_websites, hash_id=hash_id,
                           current_website=active_website, form=auth_settings_form, ssl_form=ssl_form,
                           auth_success=auth_success, ssl_success=ssl_success)


@dashboard_bp.route('/dashboard/<hash_id>/settings', methods=('GET', 'POST'))
@login_required
def website_settings(hash_id):
    """
    Show and save general settings for websites
    :param hash_id:
    :return:
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)

    success = None
    website_settings_form = WebsiteSettingsForm(request.form, active_website=active_website)

    if helpers.validate_form_on_submit(website_settings_form):
        active_website.ip_address = website_settings_form.ip_address.data
        active_website.save_visitor_logs = website_settings_form.visitor_logs.data
        active_website.cache_time = website_settings_form.cache_time.data

        result = active_website.save()
        if result['result']:
            success = 1

    website_settings_form.ip_address.data = active_website.ip_address if active_website.ip_address else ""
    website_settings_form.visitor_logs.data = 1 if active_website.save_visitor_logs else 0

    return render_template(
        "website_settings.html",
        section="settings",
        websites=all_websites,
        hash_id=hash_id,
        current_website=active_website,
        form=website_settings_form,
        success=success
    )


@dashboard_bp.route('/dashboard/<hash_id>/dns_records', methods=('GET', 'POST'))
@login_required
def website_dns_records(hash_id):
    """
    Show and modify DNS records for website
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)

    args = edit_dns_records(hash_id)
    args.update({"section": "dns_records", "active_step": None})
    return render_template("website_dns_records.html", **args) if type(args) is dict else args


@dashboard_bp.route('/dashboard/<hash_id>/under-attack')
@login_required
def under_attack(hash_id):
    """
    Notify Deflect that their site is under attack
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)

    args = {
        "websites": all_websites,
        "hash_id": hash_id,
        "current_website": active_website
    }

    status = request.args.get('status')
    if status == "1":
        active_website.under_attack = 1
        active_website.save()
        current_app.redminer.create_site_under_attack_request(active_website)
        return redirect('/dashboard/{}/under-attack'.format(hash_id))

    return render_template("under_attack.html", **args)


@dashboard_bp.route('/dashboard/<hash_id>/rescan')
@login_required
def rescan_records(hash_id):
    """
    Rescan zone file records. Wipe everything, start a scan in a separate thread and redirect to waiting page.
    """
    all_websites, active_website = check_websites(hash_id)
    current_app.db.wipe_all_records_for_website(active_website.id)
    threading.Thread(target=fetch_dns_records, args=(active_website, current_app.db, )).start()

    return redirect("/dashboard/{0}/setup/1".format(hash_id))


@dashboard_bp.route('/dashboard/<hash_id>/users', methods=['GET', 'POST'])
@login_required
def website_users(hash_id):
    """
    Show the users associated with the website
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)
    result = None

    new_user_form = NewUser(request.form)
    if helpers.validate_form_on_submit(new_user_form):
        result = DataService.add_user_to_website(active_website, new_user_form.email.data, new_user_form.role.data)

    users = DataService.get_users_by_hash_id(hash_id) if current_user.role == 0 else []

    return render_template("website_users.html", websites=all_websites, hash_id=hash_id, current_website=active_website,
                           section="users", users=users, form=new_user_form, result=result, current_user=current_user)


@dashboard_bp.route('/dashboard/<hash_id>/users/delete/<user_id_to_delete>')
@login_required
def delete_website_user(hash_id, user_id_to_delete):
    """
    Delete website user. Only the owner (creator) of website is allowed.
    """
    all_websites, active_website = check_websites(hash_id)
    # delete the user from the permissions table, ONLY if you are the owner.
    if active_website.creator_id == current_user.id:
        DataService.delete_user_from_website(active_website, user_id_to_delete)
        return redirect("/dashboard/{0}/users".format(hash_id))

    check_setup_state(active_website, hash_id)
    users = DataService.get_users_by_hash_id(hash_id) if current_user.role == 0 else []
    new_user_form = NewUser(request.form)
    return render_template("website_users.html", websites=all_websites, hash_id=hash_id, current_website=active_website,
                           section="users", users=users, form=new_user_form, current_user=current_user)


@dashboard_bp.route('/dashboard/<hash_id>/setup/delete')
@login_required
def delete_website_simple(hash_id):
    """
    Delete a website before it was setup. Only the owner (creator) of website is allowed to do this.
    """
    all_websites, active_website = check_websites(hash_id)
    if active_website.creator_id == current_user.id:
        result = DataService.delete_website_simple(active_website, current_user)
        response = render_template("confirmations/confirmation_simple_delete.html", websites=all_websites,
                                   result=result['result'])
        return response


@dashboard_bp.route('/dashboard/<hash_id>')
@login_required
def dashboard_website(hash_id):
    """
    When people access /dashboard/site_hash. This call signature is a bit different than the others (redirect at the
    end), so we don't want to use the check_status() method.
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)
    return redirect("/dashboard/{0}/stats".format(hash_id))


"""

Basic routes, general

"""


@dashboard_bp.route('/dashboard')
@login_required
def dashboard_index():
    """
    Root of the users' dashboard. If he/she has no websites, render the template to tell you to add one. If there is
    at least 1 website, choose the first one and redirect to it. It will then be checked for setup or show data.
    """
    websites = DataService.get_websites()
    if not websites:
        return render_template('dashboard_no_websites.html', user=current_user)

    first_website = websites[0].hex_hash()
    return redirect('/dashboard/{0}'.format(first_website))


@dashboard_bp.route('/website/add', methods=['GET', 'POST'])
@login_required
def add_website():
    """
    Lets the user add a website to his/her dashboard
    """
    check_password_reset()
    websites = check_no_websites_for_user()
    new_website_form = NewWebsiteForm(request.form)
    if helpers.validate_form_on_submit(new_website_form):
        url = new_website_form.url.data
        ip_address = ''
        new_website = DataService.add_website(url, current_user, ip_address)
        if new_website:
            DataService.add_permission(new_website)
            multiprocessing.Process(target=MiscUtils.fetch_dns_records, args=(new_website, current_app.db, )).start()
            return redirect("/dashboard/{0}".format(new_website.hex_hash()))
        else:
            return render_template('website_add.html', websites=websites, form=new_website_form, urlerror=1)

    return render_template('website_add.html', websites=websites, form=new_website_form)


@dashboard_bp.route('/settings/<updated_setting>', methods=['POST', 'GET'])
@login_required
def update_settings(updated_setting=None):
    """
    Update the user settings
    """
    result = None
    message = None
    websites = check_no_websites_for_user()
    email_form = NewEmail(request.form)
    password_form = NewPassword(request.form)

    if request.method == "GET" or (request.method == "POST" and updated_setting == "password"):
        email_form.new_email.process_data(current_user.email)

    if updated_setting == "email" and request.method == "POST" and helpers.validate_form_on_submit(email_form):
        try:
            DataService.update_user_email(email_form.new_email.data)
            result = 1
        except MySQLdb.IntegrityError:
            result = None
            message = "Email already exists."

    if updated_setting == "password" and request.method == "POST" and helpers.validate_form_on_submit(password_form):
        before_password_state = current_user.password_reset
        DataService.update_user_password(password_form.new_password_2.data)
        if not before_password_state:
            return redirect("/dashboard")
        result = 2

    return render_template('settings.html', websites=websites, email_form=email_form,
                           password_form=password_form, result=result, user=current_user, message=message)


"""

Setup methods and routes

"""


def check_setup_progress(website, step, hash_id):
    if website.status == -1:
        raise Exceptions.SiteSetupDone(hash_id)
    if step > website.status:
        logging.error("Current status is at {0}, trying to access {1}".format(website.status, step))
        raise Exceptions.WrongSetupStep(hash_id, website.status)


@dashboard_bp.route('/dashboard/<hash_id>/setup/0')
@dashboard_bp.route('/dashboard/<hash_id>/setup/0.0')
@login_required
def setup_0(hash_id):
    """
    Setup summary, let the user know what steps he/she will be going through.
    """
    all_websites, active_website = check_websites(hash_id)
    return render_template('setup/setup_0.html', websites=all_websites, hash_id=hash_id, active_step=0)


@dashboard_bp.route('/dashboard/<hash_id>/setup/0.5', methods=('GET', 'POST', ))
@login_required
def setup_0_5(hash_id):
    """
    IP address
    """
    all_websites, active_website = check_websites(hash_id)

    form = NewWebsiteIPForm(request.form)
    if helpers.validate_form_on_submit(form):
        ip_address = form.ip_address.data
        active_website.ip_address = ip_address
        active_website.save()
        return redirect("/dashboard/{0}/setup/1".format(hash_id))

    form.ip_address.data = active_website.ip_address if active_website.ip_address else ''

    return render_template('setup/setup_0_5.html', form=form, websites=all_websites, hash_id=hash_id, active_step=0.5)


@dashboard_bp.route('/dashboard/<hash_id>/setup/1', methods=['GET', 'POST'])
@dashboard_bp.route('/dashboard/<hash_id>/setup/1.0', methods=['GET', 'POST'])
@login_required
def setup_1(hash_id):
    """
    Step 1 is edit your DNS zone file records.
    """
    args = edit_dns_records(hash_id)
    return render_template("setup/setup_1.html", **args)


@dashboard_bp.route('/dashboard/<hash_id>/setup/delete_record')
@login_required
def setup_1_delete_record(hash_id):
    """
    Delete a record from the DNS zone file
    """
    if request.args["action"] == "delete_record":
        record_id = request.args["record_id"]
        _, active_website = check_websites(hash_id)
        result, error = DataService.delete_record_for_website(record_id)

        return jsonify({"result": 1, "error": None}) if error is None else jsonify({"result": 0, "error": error})


@dashboard_bp.route('/dashboard/<hash_id>/setup/1.5')
@login_required
def setup_1_5(hash_id):
    """
    User has simply confirmed that everything is OK. Save the state and redirect to step 2.
    Make sure they have at least 1 record before moving forward.
    """
    _, active_website = check_websites(hash_id)

    active_website.status = 2
    active_website.save()
    return redirect("/dashboard/{0}/setup/2".format(hash_id))


@dashboard_bp.route('/dashboard/<hash_id>/setup/2', methods=['GET', 'POST'])
@dashboard_bp.route('/dashboard/<hash_id>/setup/2.0', methods=['GET', 'POST'])
@login_required
def setup_2(hash_id):
    """
    Step 2 is enter your admin config details (banjax info)
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_progress(active_website, 2, hash_id)
    auth_settings_form = SecuritySettingsForm(request.form)

    if helpers.validate_form_on_submit(auth_settings_form):
        # save new settings
        active_website = DataService.update_auth_settings(
            active_website,
            auth_settings_form.auth_pass.data,
            auth_settings_form.admin_key.data
        )

        active_website.status = 2.5
        active_website.save()

        return redirect("/dashboard/{0}/setup/2.5".format(hash_id))

    # pre-fill values where possible (except password, which cannot be done)
    auth_settings_form.admin_key.data = active_website.admin_key if active_website.admin_key else ""

    return render_template("setup/setup_2.html", form=auth_settings_form, websites=all_websites,
                           current_website=active_website, from_setup=1, active_step=2)


@dashboard_bp.route('/dashboard/<hash_id>/setup/2.1')
@login_required
def setup_2_1(hash_id):
    """
    Step 2.1 is skip banjax auth
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_progress(active_website, 2.0, hash_id)
    active_website.status = 2.5
    active_website.save()

    return redirect("/dashboard/{0}/setup/2.5".format(hash_id))


@dashboard_bp.route('/dashboard/<hash_id>/setup/2.5', methods=['GET', 'POST'])
@login_required
def setup_2_5(hash_id):
    """
    Step 2.5 is SSL cert files
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_progress(active_website, 2.5, hash_id)

    ssl_form = SecuritySSLForm(request.form)
    active_website = make_datetime_readable(active_website)

    if request.method == "POST":

        if request.args.get("save") == "ssl_files" and helpers.validate_form_on_submit(ssl_form):
            save_ssl_files(active_website, ssl_form, True)

            active_website.status = 3
            active_website.save()

            # create redmine ticket
            admin_url = "{0}/manage/{1}".format(current_app.config["ADMIN_HOST"], active_website.id)
            current_app.redminer.create_system_ticket(
                "Validate confiuration and set-up on Deflect for website: {0}.".format(active_website.url),
                "See website on dashadmin: {0}".format(admin_url),
                [current_user, active_website]
            )

            return redirect("/dashboard/{0}/setup/3".format(hash_id))

    ssl_form.ssl_checkbox.data = 1 if active_website.use_ssl else 0

    return render_template("setup/setup_2_5.html", current_website=active_website, ssl_form=ssl_form,
                           websites=all_websites, active_step=2.5)


@dashboard_bp.route('/dashboard/<hash_id>/setup/3')
@dashboard_bp.route('/dashboard/<hash_id>/setup/3.0')
@dashboard_bp.route('/dashboard/<hash_id>/setup/4')
@dashboard_bp.route('/dashboard/<hash_id>/setup/4.0')
@dashboard_bp.route('/dashboard/<hash_id>/setup/5')
@dashboard_bp.route('/dashboard/<hash_id>/setup/5.0')
@dashboard_bp.route('/dashboard/<hash_id>/setup/6')
@dashboard_bp.route('/dashboard/<hash_id>/setup/6.0')
@login_required
def setup_3(hash_id):
    """
    DNS zone file editing is done, move on to the last steps
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_progress(active_website, 3, hash_id)
    return render_template(
        'setup/setup_3.html', websites=all_websites, hash_id=hash_id, website=active_website, active_step=3
    )


@dashboard_bp.route('/dashboard/<hash_id>/setup/3.5')
@login_required
def setup_3_5(hash_id):
    """
    User has apparently changed their ns, try checking for dns resolving of their domain.
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_progress(active_website, 3.5, hash_id)
    active_website.status = 4
    active_website.save()
    return redirect("/dashboard/{0}/setup/4".format(hash_id))


@dashboard_bp.route('/dashboard/<hash_id>/setup/4.5')
@login_required
def setup_4_5(hash_id):
    """
    NS has been confirmed as moved
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_progress(active_website, 4, hash_id)
    active_website.status = 5
    active_website.save()
    return redirect("/dashboard/{0}/setup/5".format(hash_id))


def edit_dns_records(hash_id):
    """
    DNS zone file parser.
    The data returned by this view is the same for setting up your DNS zone file and in the "settings" tab.
    Can either return a settings dict, or a redirect instance. Check type to know what to do with this response.
    """
    all_websites, active_website = check_websites(hash_id)
    records = DataService.get_records_for_website(hash_id, active_website)
    success, error = None, None

    # new DNS record submission
    form = NewDNSZoneFileRecord(request.form)
    if helpers.validate_form_on_submit(form):

        args = (
            form.record_type.data,
            form.record_name.data,
            form.record_value.data,
            None if form.record_priority.data == "" else form.record_priority.data,
            None if form.record_weight.data == "" else form.record_weight.data,
            None if form.record_port.data == "" else form.record_port.data,
            0,
            active_website.id
        )
        success, error = current_app.db.add_record(args)
        records = DataService.get_records_for_website(hash_id, active_website)

    return {
        "error": error,
        "success": success,
        "websites": all_websites,
        "hash_id": hash_id,
        "form": form,
        "current_website": active_website,
        "records": records,
        "fetching": active_website.scan_in_progress,
        "active_step": 1
    }

"""

Checking methods to be sure the sites you are trying to see are yours, that your hash is valid and that you indeed
have sites in your account.

"""


def check_password_reset():
    """
    Before doing anything, make sure users change their passwords.
    """
    if not current_user.password_reset:
        raise Exceptions.UserNeedsToChangePassword


def check_websites(hash_id):
    """
    User must have at least 1 website registered to the dashboard to continue
    """
    check_password_reset()

    all_websites, active_website = DataService.get_website_data(hash_id)
    if active_website is None or not all_websites:
        raise Exceptions.InvalidWebsite
    return all_websites, active_website


def check_setup_state(active_website, hash_id):
    """
    State -1 means that all is done, the website is setup with Deflect
    """
    if active_website.status != -1:
        raise Exceptions.WebsiteNeedsSetup(hash_id, active_website.status)


def check_status(hash_id, template_name, section):
    """
    If the website is setup properly, show the requested template, otherwise redirect to setup
    """
    all_websites, active_website = check_websites(hash_id)
    check_setup_state(active_website, hash_id)
    return render_template(template_name, websites=all_websites, hash_id=hash_id, current_website=active_website,
                           section=section)


def check_no_websites_for_user():
    """
    Make sure there is at least 1 website for this user.
    """
    websites = DataService.get_websites()
    return websites

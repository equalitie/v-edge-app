import threading

from flask import Blueprint, render_template, current_app, request
from flask_babel import lazy_gettext as ___
from flask_login import current_user
from flask_admin import helpers

from frontend.forms.signup_login import SignupForm
import lib.Utils as MiscUtils
import lib.DBService as DataService


signup_bp = Blueprint('signup', __name__)


def send_confirmation_emails(user, plain_text_password, signup_form):
    """
    Send various confirmation emails after signup
    """
    current_app.mail_sender.notify_user_signed_up(user, plain_text_password)
    if current_app.config['SERVER_ENV'] != "DEV":
        current_app.mail_sender.notify_deflect(user, signup_form.domain_name.data, signup_form.ip_address.data,
                                           signup_form.pgp_key.data, request.headers)


def check_email_or_website(email, url):
    email_exists = current_app.db.get_user_by_email(email)
    if email_exists:
        return True, "email"

    clean_url = MiscUtils.get_clean_url(url)
    website_exists = current_app.db.get_website_by_url(clean_url)
    if website_exists:
        return True, "website"

    return False, ""


@signup_bp.route('/signup', methods=('GET', 'POST'))
def index():
    """
    Create a new user
    """
    signup_form = SignupForm()

    # if form is submitted and validated
    if helpers.validate_form_on_submit(signup_form):

        # check if email or website already exists
        exists, which = check_email_or_website(signup_form.email.data, signup_form.domain_name.data)
        if exists:
            msg = ___("%s already exists." % which)
            return render_template('signup.html', current_user=current_user, form=signup_form, error=msg)

        plain_text_password, hashed_password, password_salt = DataService.generate_new_user_password()

        # create a new user
        user = DataService.create_user(signup_form.email.data, hashed_password, password_salt)

        # add website to websites table.
        website = DataService.add_website(signup_form.domain_name.data, user, signup_form.ip_address.data)

        # notify user that login worked, send him/her password in email
        send_confirmation_emails(user, plain_text_password, signup_form)

        # add user to permissions. role 0 means manager for now.
        DataService.add_permission(website, user)

        # scan your DNS records while we wait. this is threaded so we don't block the whole process.
        threading.Thread(target=MiscUtils.fetch_dns_records, args=(website, current_app.db, )).start()

        # all went well. signup confirmation, check your email.
        return render_template('signup_confirmation.html')

    return render_template('signup.html', current_user=current_user, form=signup_form)

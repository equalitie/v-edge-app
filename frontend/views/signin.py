from flask import redirect, render_template, request, Blueprint, current_app
from flask_admin import helpers
from flask_login import login_user, current_user
from frontend.forms.signup_login import LoginForm, ForgotPasswordForm, ChangePasswordForm
from lib.models.User import User
from flask_babel import lazy_gettext as ___
import lib.DBService as DBService
import hashlib
import time
login_bp = Blueprint('login', __name__)


@login_bp.route('/login', methods=('GET', 'POST'))
@login_bp.route('/signin', methods=('GET', 'POST'))
def main_login():
    """
    Login handler.
    """
    login_form = LoginForm(request.form)

    # form is submitted and has been validated
    if helpers.validate_form_on_submit(login_form):
        login_user(login_form.user)

    if current_user.is_authenticated():
        return redirect("/dashboard")

    return render_template(
        'signin.html',
        current_user=current_user,
        form=login_form
    )


def create_hash(user):
    value = hashlib.sha1("%s+%s+%s" % (str(user.date_joined), str(user.id), str(time.time())))
    return value.hexdigest()


@login_bp.route("/forgotpassword", methods=('GET', 'POST'))
def forgot_password():
    """
    Forgotten password handler
    """
    reset_password_form = ForgotPasswordForm(request.form)

    if helpers.validate_form_on_submit(reset_password_form):
        # all this should go in the DBService file
        user_data = current_app.db.get_user_by_email(reset_password_form.email.data)
        if not user_data:
            error_msg = ___("Could not find user. Please check the email and <a href='/forgotpassword'>try again</a>.")
            return render_template("forgotpassword.html", success=-1, message=error_msg)

        user = User(user_data)
        user.reset_link = create_hash(user)
        user.save()

        email_result = current_app.mail_sender.send_reset_link(user)
        if email_result is None:
            result = -1
            message = ___("There was an error sending your email reset link.")
        else:
            result = 1
            message = ___("Please check your inbox, we have sent you an email reset link.")

        return render_template("forgotpassword.html", success=result, message=message)

    return render_template("forgotpassword.html", form=reset_password_form)


@login_bp.route("/changepassword/<hash_id>", methods=('GET', 'POST'))
def change_password(hash_id):
    """
    Reset the users' password

    - find the hash
    - if found, ask for new password
    - save hashed pwd
    - update reset link to empty
    - update changed password to 1
    - confirmation message
    """
    alleged_user = current_app.db.get_user_by_reset_link(hash_id)
    if not alleged_user:
        user_error = ___("Could not find reset link. Please double check the link sent to your email.")
        return render_template("changepassword.html", user_error=user_error)

    # most of this should also go into the DBService.
    user = User(alleged_user)
    change_password_form = ChangePasswordForm(request.form)
    if helpers.validate_form_on_submit(change_password_form):
        # do the actual reset
        p1, p2 = change_password_form.password1.data, change_password_form.password2.data
        result = DBService.update_user_password(p1, user)

        # clear these values to make sure password can't be reset again with same link
        user.reset_link = ""
        user.password_reset = 1
        user.save()

        # render template depending on how it went
        if result["result"]:
            return render_template("changepassword.html", success=1)
        else:
            user_error = ___("There was an error saving your new password please try again.")
            return render_template("changepassword.html", user_error=user_error)

    return render_template("changepassword.html", form=change_password_form)
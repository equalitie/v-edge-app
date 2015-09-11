from wtforms import fields, validators
from flask import current_app, request
import bcrypt
import frontend.utils.signup_restrictions as signup_restrictions
from lib.models.User import User
from lib.Utils import get_clean_url, add_to_failed_attempts, get_failed_attempts
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class LoginForm(Form):
    """
    WTForm for login.
    """
    user = None

    login = fields.StringField(
        validators=[validators.required(), validators.email()], description={
            'placeholder': ___('email'),
        }
    )
    password = fields.PasswordField(
        validators=[validators.required()], description={
            'placeholder': ___('password'),
        }
    )

    def validate_login(self, field):
        user = self.fetch_user_by_email(field.data)

        failed_signin_attempts = get_failed_attempts(request.remote_addr, field.data)
        if failed_signin_attempts > 2:
            raise validators.StopValidation(
                ___('You have attempted too many failed logins. Please try again in 5 minutes.')
            )

        if not self.password.data:
            raise validators.ValidationError(___('Invalid password'))

        # if we got a user, check the password.
        stored_pwd = user.password_hash
        stored_salt = user.password_salt
        hashed_pwd = bcrypt.hashpw(self.password.data.encode('utf-8'), stored_salt.encode('utf-8'))

        if stored_pwd != hashed_pwd:
            add_to_failed_attempts(request.remote_addr, field.data)
            raise validators.ValidationError(___('Invalid password'))

        self.user = user

    @staticmethod
    def fetch_user_by_email(email):
        user_data = current_app.db.get_user_by_email(email)
        if user_data is None:
            raise validators.ValidationError(___('Invalid user'))
        user = User(user_data)
        return user


class SignupForm(Form):
    """
    WTForm for user signup.
    Field titles will be overridden with their localized version after they are initialized.
    """
    domain_name = fields.StringField(
        ___('Domain name *'), validators=[validators.required(), validators.URL()], description={
            'placeholder': ___("http://www.example.com"), 'req': 1
        }
    )
    ip_address = fields.StringField(
        ___('IP Address *'), validators=[validators.required(), validators.IPAddress()], description={
            'placeholder': "129.128.127.126", 'req': 1
        }
    )
    email = fields.StringField(
        ___('Email *'), validators=[validators.required(), validators.email()], description={
            'placeholder': "john@smith.com", 'req': 1
        }
    )
    pgp_checkbox = fields.BooleanField(___('I use PGP'))
    pgp_key = fields.TextAreaField(
        ___('PGP Key'), description={
            'placeholder': ___('PGP Key'), 'req': 0
        }
    )

    def validate_domain_name(self, field):
        clean_url = get_clean_url(field.data)
        email_address = self.email.data
        if email_address in signup_restrictions.allowed_values:
            if clean_url not in signup_restrictions.allowed_values[email_address]:
                raise validators.ValidationError(___('You are not allowed to sign up for this website.'))


class ForgotPasswordForm(Form):
    """
    Users have forgotten their password form
    """
    email = fields.StringField(
        ___("Email *"), validators=[validators.required(), validators.email()], description={
            'placeholder': "john@smith.com"
        }
    )


class ChangePasswordForm(Form):
    """
    Form to update a user's password
    """
    password1 = fields.PasswordField(
        ___("Password"), validators=[
            validators.length(min=8),
            validators.required(),
        ], description={"placeholder": ___("New password")}
    )
    password2 = fields.PasswordField(
        "Password", validators=[
            validators.length(min=8),
            validators.required(),
        ], description={"placeholder": ___("New password (repeat)")}
    )

    def validate_password1(self, field):
        if field.data != self.password2.data:
            raise validators.ValidationError(___('Passwords do not match'))
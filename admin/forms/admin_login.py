from wtforms import form, fields, validators
from flask import current_app
from lib.models.User import User


class LoginForm(form.Form):
    """
    WTForm for login.
    """
    user = None

    login = fields.StringField(
        validators=[validators.required()], description={
            'placeholder': "user",
        }
    )
    password = fields.PasswordField(
        validators=[validators.required()], description={
            'placeholder': "password",
        }
    )

    def validate_login(self, field):
        expected_user = current_app.config["ADMIN_USER"]
        expected_password = current_app.config["ADMIN_PASSWORD"]

        if field.data != expected_user or self.password.data != expected_password:
            raise validators.ValidationError('Invalid password')

        self.user = User({"id": 0})
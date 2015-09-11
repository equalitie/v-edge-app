from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form
import lib.DBService as DBService


class NewEmail(Form):
    """
    Update your email form
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(NewEmail, self).__init__(*args, **kwargs)
    new_email = fields.TextField(___("New email"), validators=[validators.required(), validators.email()])


class NewPassword(Form):
    """
    Update your password form
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(NewPassword, self).__init__(*args, **kwargs)

    old_password = fields.PasswordField("", validators=[
        validators.required()
    ])
    new_password_1 = fields.PasswordField("", validators=[
        validators.required(),
        validators.length(min=9)
    ])
    new_password_2 = fields.PasswordField("", validators=[
        validators.required(),
        validators.length(min=9),
        validators.equal_to("new_password_1", ___("New passwords must match"))
    ])

    def validate_old_password(self, field):
        if not DBService.check_old_password(field.data.encode('utf-8')):
            raise validators.ValidationError(___("Old password does not match."))
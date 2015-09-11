from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class SecuritySettingsForm(Form):
    """
    Website admin security settings
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(SecuritySettingsForm, self).__init__(*args, **kwargs)

    auth_pass = fields.PasswordField(___("Authentication password"),
                                     validators=[validators.length(min=8), validators.required()],
                                     description={"placeholder": ___("New authentication password")})

    admin_key = fields.StringField(
        "Admin access", validators=[], description={
            'placeholder': "ex: wp-admin"
        }
    )

    def validate_admin_key(self, field):
        if field.data.startswith("http"):
            raise validators.ValidationError(___("Cannot start with 'http' - this field should contain the URL component for your admin interface."))

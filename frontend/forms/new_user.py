from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class NewUser(Form):
    """
    Add a new user to Deflect dashboard.
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(NewUser, self).__init__(*args, **kwargs)

    email = fields.StringField(
        validators=[validators.required(), validators.email()], description={
            'placeholder': ___("Enter email"),
        }
    )
    role = fields.SelectField("", choices=[("0", ___("Administrator"))],
                              validators=[validators.required()])
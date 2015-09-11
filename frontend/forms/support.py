from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class SupportForm(Form):
    """
    Send a support ticket
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(SupportForm, self).__init__(*args, **kwargs)

    comment = fields.TextAreaField(___("Comment"), validators=[validators.required()])
    support_type = fields.SelectField("", coerce=int, validators=[validators.required()])
    website_concerned = fields.SelectField("")
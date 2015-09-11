from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class ServerSettingsForm(Form):
    """
    Server settings
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        kwargs.setdefault('cache_time', kwargs['active_website'].cache_time)
        super(WebsiteSettingsForm, self).__init__(*args, **kwargs)

    ip_address = fields.StringField(
        ___("IP address *"), validators=[validators.required(), validators.IPAddress()], description={
            'placeholder': "129.128.127.126"
        }
    )

    visitor_logs = fields.BooleanField(___("Collect visitor logs"))

    minutes = [10, 60, 120, 300]
    choices = [(str(x), str(x)) for x in minutes]
    cache_time = fields.SelectField(
        ___("Website cache minutes"), choices=choices, validators=[validators.required()]
    )

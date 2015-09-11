from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class NewServerNameForm(Form):
    """
    Add a new name server to your dashboard
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(NewServerForm, self).__init__(*args, **kwargs)

    name = fields.TextField(___("Server Name"), validators=[validators.required()], description={
        "placeholder": ___("Server Name")
    })


class NewServerIPForm(Form):
    """
    Add new IP to server
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(NewServerIPForm, self).__init__(*args, **kwargs)

    ip_address = fields.StringField(
        ___("IP address *"), validators=[validators.required(), validators.IPAddress()], description={
            'placeholder': ___("IP address: 129.128.127.126")
        }
    )

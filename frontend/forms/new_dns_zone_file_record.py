from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form

import socket
import re


class NewDNSZoneFileRecord(Form):
    """
    To add a new DNS zone file record in setup step 2
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(NewDNSZoneFileRecord, self).__init__(*args, **kwargs)

    record_types = ['NS', 'MX', 'A', 'CNAME', 'TXT', 'SRV']
    choices = [(x, x) for x in record_types]

    record_type = fields.SelectField("", choices=choices, validators=[validators.required()], default='A')
    record_name = fields.TextField("", validators=[validators.required()], description={
        'placeholder': ___("Name"),
    })
    record_value = fields.TextField("", validators=[validators.required()], description={
        'placeholder': ___("Value"),
    })
    record_priority = fields.TextField("", default="", description={
        'placeholder': ___("Priority"),
    })
    record_weight = fields.TextField("", default="", description={
        'placeholder': ___("Weight"),
    })
    record_port = fields.TextField("", default="", description={
        'placeholder': ___("Port"),
    })
    choices = [("1", ___("Use Deflect")), ("0", ___("Don't use Deflect"))]
    record_use_deflect = fields.SelectField("", choices=choices, default='0')

    @staticmethod
    def check_required_numerical_field(name, data):
        if data is None:
            raise validators.ValidationError(___("Please provide a {} value.".format(name)))
        try:
            float(data)
        except ValueError:
            raise validators.ValidationError(___("Incorrect {} value.".format(name)))

    @staticmethod
    def check_valid_dns_name(hostname):
        # Shamelessly lifted from
        # https://stackoverflow.com/questions/2532053/validate-a-hostname-string
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def validate_record_type(self, field):
        # A records
        if field.data == "A":
            try:
                socket.inet_aton(self.record_value.data)
            except socket.error:
                raise validators.ValidationError(___("Incorrect A record value."))

        # mx records
        if field.data == "MX":
            self.check_required_numerical_field("priority", self.record_priority.data)

        # SRV records
        if field.data == "SRV":
            self.check_required_numerical_field("priority", self.record_priority.data)
            self.check_required_numerical_field("weight", self.record_weight.data)

        if field.data == "CNAME":
            if not self.check_valid_dns_name(self.record_value.data):
                raise validators.ValidationError(___("Invalid value for CNAME."))

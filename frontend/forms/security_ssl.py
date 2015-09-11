from wtforms import fields, validators
from flask import request
from flask_babel import lazy_gettext as ___
from flask_wtf import Form
import string


class SecuritySSLForm(Form):
    """
    SSL files upload form
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(SecuritySSLForm, self).__init__(*args, **kwargs)

    ssl_checkbox = fields.BooleanField(___("My website uses SSL"))
    certificate_file = fields.FileField(___("Certificate file"))
    key_file = fields.FileField(___("Key file"))
    chain_file = fields.FileField(___("Chain file"))

    def is_allowed(self, ext, x):
        return '.' in x and x.rsplit('.', 1)[1] in ext

    def is_basic_chars(self, filename):
        allowed_chars = string.ascii_lowercase + "-_." + string.digits
        return True if not filename.lower().strip(allowed_chars) else False

    def validate_ssl_checkbox(self, field):
        """
        If the checkbox is ON, we should have at least a certificate file and a key file.
        """
        if field.data:
            if not self.certificate_file.name or not self.key_file.name:
                raise validators.ValidationError(___('Certificate file and key file needed.'))

    def validate_certificate_file(self, field):
        cert_file = request.files[field.name]
        if self.ssl_checkbox.data:
            if not cert_file or not self.is_allowed("crt", cert_file.filename):
                raise validators.ValidationError(___('Certificate file must have a .crt extension.'))

    def validate_key_file(self, field):
        if self.ssl_checkbox.data:
            key_file = request.files[field.name]
            if not key_file or not self.is_allowed("key", key_file.filename):
                raise validators.ValidationError(___('Key file must have a .key extension.'))

    def validate_chain_file(self, field):
        if self.ssl_checkbox.data:
            chain_file = request.files[field.name]
            if chain_file:
                if not self.is_basic_chars(chain_file.filename):
                    raise validators.ValidationError(___(('Chain file name must only contain alphanumeric '
                                                          'characters, full stops, commas, underscores and dashes.')))

from wtforms import form, fields, validators


class SaveDNSData(form.Form):
    """
    Text field to paste/edit your dns zone file data.
    """
    zone_file_data = fields.TextAreaField("", validators=[validators.required()])
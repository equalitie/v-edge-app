from wtforms import fields, validators
from flask_babel import lazy_gettext as ___
from flask_wtf import Form


class IncidentForm(Form):
    """
    Send an incident report
    """
    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(IncidentForm, self).__init__(*args, **kwargs)

    server_ip = fields.SelectField(___("Choose server *"))
    incident_date_time = fields.StringField(
        ___("Incident date and time *"), validators=[validators.required()], description={
            'placeholder': "May 25th, 2014"
        }
    )
    problem_description = fields.TextAreaField(
        ___("Problem description *"), validators=[validators.required()], description={
            'placeholder': ___("What were you doing? Where did you come from?")
        }
    )
    email = fields.StringField(
        ___("Contact email"), description={
            'placeholder': "john@smith.com",
            "explanation": "This field is optional."
        }
    )
    pt1 = ___("This field is optional.")
    pt2 = ___("How to find the via header.")

    via_header = fields.StringField(
        ___("Via header"), description={'placeholder': "", "explanation1": pt1, "explanation2": pt2}
    )

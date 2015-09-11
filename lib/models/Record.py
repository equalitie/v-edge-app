from flask import current_app


class Record(object):

    hostname = None
    value = None
    id = None
    priority = None
    weight = None
    type = None
    website_id = None
    deflect = None
    port = None

    def __init__(self, data=None):
        """
        Fill out attributes on init
        """
        if data is not None:
            for k, v in data.iteritems():
                setattr(self, k, v)

    def create(self):
        """
        Create new dns zone file record
        """
        return current_app.db.create_record(self)
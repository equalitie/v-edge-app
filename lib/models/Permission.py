from flask import current_app


class Permission(object):

    user_id = None
    website_id = None
    role = None

    def __init__(self, data=None):
        """
        Fill out attributes on init
        """
        if data is not None:
            for k, v in data.iteritems():
                setattr(self, k, v)

    def create(self):
        """
        Create new website
        """
        return current_app.db.create_permission(self)
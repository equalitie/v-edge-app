import uuid
import binascii

from flask import current_app

import lib.Utils as MiscUtils


class Server(object):

    def __init__(self, data=None):
        """
        Fill out attributes on init
        """

        self.id = None
        self.ip_address = None
        self.name = None
        self.admin_key = None
        self.banjax_auth_hash = None
        self.hidden_domain = None
        self.status = None
        self.hash_id = None
        self.creator_id = None
        self.scan_in_progress = None
        self.nsinfo = None
        self.awstats_password = None
        self.save_visitor_logs = None
        self.use_ssl = None
        self.ssl_certificate_file_upload_date = None
        self.ssl_key_file_upload_date = None
        self.ssl_chain_file_upload_date = None
        self.cache_time = None
        self.under_attack = None

        if data is not None:
            for k, v in data.iteritems():
                setattr(self, k, v)

    def hex_hash(self):
        return binascii.b2a_hex(self.hash_id)

    @staticmethod
    def create_hash_id():
        """
        Create a unique hash for every website
        """
        key = uuid.uuid4()
        return key.bytes

    @staticmethod
    def create_awstats_password():
        """
        Create a password for awstats
        """
        return uuid.uuid4()

    def create(self):
        """
        Create new website
        """
        self.hash_id = self.create_hash_id()
        self.hidden_domain = MiscUtils.generate_hidden_domain()
        self.awstats_password = self.create_awstats_password()
        return current_app.db.create_website(self)

    def save(self):
        """
        Update the website record
        """
        return current_app.db.save_server(self)

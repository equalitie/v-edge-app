from redmine import Redmine
import collections
import requests.exceptions
import logging


class Redminer(object):

    """
    Create redmine issues from here.
    """

    project_id = 23  # this can also be a string ('signups')
    subject = ""
    subject_prefix = ""
    description = ""
    tracker = "support"

    def __init__(self, url, api_key, server_env, support_subject_values):
        """
        Init the Redminer. The subject should always be subject_prefix + subject. The prefix is for DEV and STAGING
        environments, so we know the bugs are not real.
        """
        self.r = Redmine(url=url, key=api_key, requests={'verify': False})
        self.subject_prefix = "{0}: ".format(server_env) if self.subject_prefix != "PRODUCTION" else ""
        self.support_subject_types = collections.defaultdict(lambda: 0, support_subject_values)

    def get_subject(self, support_subject_value):
        """
        Always use this method to set the subject, it concatenates the prefix and the actual subject
        """
        return "{0}{1}".format(self.subject_prefix, self.support_subject_types[support_subject_value])

    def get_system_subject(self, subject):
        return "{0}{1}".format(self.subject_prefix, subject)

    @staticmethod
    def get_description(comment, data):
        """
        Packages all data needed for a description.
        Here, `comment` is a string from the user. `data` is a list of dicts to be unpacked into a list of items
        and jammed in the description for now.
        """
        # if there's no data, just return the comment.
        if not data:
            return "{0}".format(comment)

        str_from_data = ""
        for d in data:
            if type(d) is dict:
                items = d.iteritems()
            else:
                items = d.__dict__.iteritems()
            skip_fields = [
                "hash_id", "password_hash", "password_salt", "banjax_auth_hash", "awstats_password",
                "admin_key", "banjax_auth_salt", "hidden_domain", "reset_link", "password_reset"
            ]
            str_from_data += "\n".join(["{0}: {1}".format(k, v) for k, v in items if k not in skip_fields])
            str_from_data += "\n\n"
        # there's binary in there so just ignore the blobs that cannot be decoded
        return "Message: {0}\n\n{1}".format(comment, str_from_data.decode('utf-8', 'ignore'))

    def create_user_ticket(self, support_type, comment, data):
        """
        Create a new issue for a user support ticket
        """
        subject = self.get_subject(support_type)
        description = self.get_description(comment, data)
        return self.send_ticket(subject, description)

    def create_site_under_attack_request(self, website):
        """
        For users toggling the "my site is under attack" button
        """
        subject = "Site under attack: {}".format(website.url)
        self.create_system_ticket(subject, "This website has requested additional protection: ", [website])

    def create_system_ticket(self, subject, comment, data):
        """
        Internal messages, communications.
        """
        description = self.get_description(comment, data)
        self.send_ticket(self.get_system_subject(subject), description)

    def create_ssl_files_ticket(self, status, website, uploads):
        """
        Create a ticket for SSL cert files uploaded
        """
        subject = "New SSL file status for website id {0}: {1}".format(website.id, website.url)
        description = "User has SSL set to:  {}.".format(status)
        self.send_ticket(self.get_system_subject(subject), description, uploads)

    def send_ticket(self, subject, description, uploads=None):
        """
        Create the actual ticket.
        """
        if uploads is None:
            uploads = []
        try:
            issue = self.r.issue.create(
                project_id=self.project_id,
                subject=subject,
                tracker=self.tracker,
                description=description,
                uploads=uploads
            )
            return issue
        except requests.exceptions.SSLError as e:
            logging.error("SSL Error. Could not create ticket.")
            logging.error(e.message)
            return None

    def close_ticket(self):
        pass

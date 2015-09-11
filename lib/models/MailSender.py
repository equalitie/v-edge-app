from flask_mail import Message
import logging


class MailSender(object):
    """
    Different mail sending methods.
    """

    def __init__(self, mail, app):
        self.mail = mail
        self.app = app

    def notify_user_signed_up(self, user, plaintext_password):
        """
        After the user has just signed up. Send him the plaintext version of his new password.
        """
        msg_body = """Hello,\n\n
Thank you for signing up on Deflect!\n\n
Your account has been created on the Deflect Dashboard. Please login by going to https://dashboard.deflect.ca/login and using your email and this password: {0}\n
If you have any questions, please don't hesitate to contact us at deflect@equalit.ie\n\n
- The Deflect team\n""".format(plaintext_password)
        msg = Message("Welcome to Deflect!", sender=self.app.config["ADMIN_EMAIL"], recipients=[user.email])
        msg.body = msg_body

        try:
            self.mail.send(msg)
        except Exception as e:
            logging.error("could not send signup email: {}".format(e.message))

    def notify_deflect(self, user, server, ip, pgp, request_headers=None):
        """
        Notify the owner that a new signup has occurred.
        """
        if request_headers is None:
            request_header_string = "Could not retrieve request headers."
        else:
            header_items = ["{0}: {1}".format(k, v) for k, v in request_headers.iteritems()]
            request_header_string = "\n".join(header_items)

        msg_body = '''A new user (%s) has signed up for deflect.\n
- server: %s
- IP: %s
- pgp key: \n\n%s\n\n
- request headers: \n\n%s
        ''' % (user.email, server, ip, pgp, request_header_string)
        msg = Message("New user signup for Deflect", sender=self.app.config["ADMIN_EMAIL"],
                      recipients=[self.app.config["ADMIN_EMAIL"]])
        msg.body = msg_body

        try:
            self.mail.send(msg)
        except Exception as e:
            logging.error("Could not send email to notify deflect of new signup: {}".format(e.message))

    def notify_of_server_deletion(self, server, user):
        """
        Notify admin that a server was deleted.
        """
        msg_body = "A new user {} has deleted their server: {} (id {})".format(user.email, server.ip, server.id)
        msg = Message("New server deletion notice", sender=self.app.config["ADMIN_EMAIL"],
                      recipients=[self.app.config["ADMIN_EMAIL"]])
        msg.body = msg_body
        try:
            self.mail.send(msg)
        except Exception as e:
            logging.error("Could not send email to notify of server deletion: {}".format(e.message))

    def notify_user_change_ns_settings(self, user, server):
        """
        Deflect has manually changed the NS settings and setup step in the DB for user, send email to them.
        """
        url = "{0}/dashboard/{1}/setup/2".format(self.app.config["DASHBOARD_HOST"], server.hex_hash())
        msg_body = '''Hi! Deflect needs you to take action in order to complete the setup process for your server: %s.
You need to change your domains' NS to the following:

%s

Once you are done, go to your dashboard and complete the setup process here: %s

If you have already changed your NS records, please log into the dashboard and complete your setup process.

- The Deflect team
                ''' % (server.url, str(server.nsinfo), url)
        msg = Message("Deflect server setup: action required on your part.", sender=self.app.config["ADMIN_EMAIL"],
                      recipients=[user.email])
        msg.body = msg_body
        try:
            self.mail.send(msg)
            return True
        except Exception, e:
            logging.error("There was an error: %s" % e.message)
            return None

    def notify_user_server_ready(self, user, server):
        """
        Last step which is triggered by the admin. Tell the user they are set to start using Deflect.
        """
        url = "{0}/dashboard/{1}".format(self.app.config["DASHBOARD_HOST"], server.hex_hash())
        msg_body = '''Congratulations, you are ready to use Deflect for your server %s!
Go to your dashboard %s to manage your settings.

- The Deflect team
                ''' % (server.ip, url)
        msg = Message("Your Deflect server is ready.", sender=self.app.config["ADMIN_EMAIL"],
                      recipients=[user.email])
        msg.body = msg_body
        try:
            self.mail.send(msg)
            return True
        except Exception, e:
            logging.error("There was an error: %s" % e.message)
            return None

    def send_reset_link(self, user):
        """
        Send the link hash to the user
        """
        url = "{0}/changepassword/{1}".format(self.app.config["DASHBOARD_HOST"], user.reset_link)
        msg_body = '''You have requested a link to reset your password. To do so, please go to:
%s

- The Deflect team
                ''' % url
        msg = Message("Your password reset link.", sender=self.app.config["ADMIN_EMAIL"],
                      recipients=[user.email])
        msg.body = msg_body
        try:
            self.mail.send(msg)
            return True
        except Exception, e:
            logging.error("There was an error: %s" % e.message)
            return None

    def send_incident_report(self, incident_dict, issue_url):
        """
        Heads up to sysops for incident reports
        """
        msg_body = '''There is a new incident report here:
{0}

This is the incident data:

{1}

Sincerely,

- Your Deflect Dashboard
                '''.format(issue_url, "\n".join(["{0}: {1}".format(k, v) for k,v in incident_dict.iteritems()]))
        msg = Message("New incident report", sender=self.app.config["SYSOPS_EMAIL"],
                      recipients=[self.app.config["SYSOPS_EMAIL"]])
        msg.body = msg_body
        try:
            self.mail.send(msg)
            return True
        except Exception, e:
            logging.error("There was an error: %s" % e.message)
            return None

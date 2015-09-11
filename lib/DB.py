import MySQLdb
from flask_login import current_user
import binascii
import logging
from flask_babel import lazy_gettext as ___


class BaseDB(object):
    """
    Common operations for DB instance.
    """
    def __init__(self, host, user, password, db):
        self.host = host
        self.user = user
        self.password = password
        self.db = db

    def connect(self):
        """
        Return a connection to the DB
        """
        return MySQLdb.connect(host=self.host, user=self.user,
                               passwd=self.password, db=self.db,
                               use_unicode=True, charset="utf8")

    def fetch_all(self, query, args=None):
        """
        Fetch multiple
        """
        connection = self.connect()
        cursor = connection.cursor(MySQLdb.cursors.SSDictCursor)
        cursor.execute(query, args)
        result = cursor.fetchall()
        cursor.close()
        connection.close()
        return result

    def fetch_one(self, query, args=None):
        """
        Fetch one
        """
        connection = self.connect()
        cursor = connection.cursor(MySQLdb.cursors.SSDictCursor)
        cursor.execute(query, args)
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        return result

    def execute_many(self, query, args=None):
        """
        Execute many (ex: multiple insert)
        """
        connection = self.connect()
        cursor = connection.cursor(MySQLdb.cursors.SSDictCursor)
        result = cursor.executemany(query, args)
        connection.commit()
        cursor.close()
        connection.close()
        return {"result": result, "lastrowid": cursor.lastrowid}

    def execute_query(self, query, args=None):
        """
        Execute query (ex: INSERT or UPDATE)
        """
        connection = self.connect()
        cursor = connection.cursor(MySQLdb.cursors.SSDictCursor)
        result = cursor.execute(query, args)
        connection.commit()
        cursor.close()
        connection.close()
        return {"result": result, "lastrowid": cursor.lastrowid}


class DB(BaseDB):

    def create_user(self, user):
        """
        Create a new user, simple insert. Signup users.
        """
        query = '''
        INSERT INTO
            users (email, password_hash, password_salt, date_joined, status)
        VALUES
            (%s, %s, %s, %s, %s)
        '''
        result = self.execute_query(query, (
            user.email, user.password_hash,
            user.password_salt, user.date_joined,
            user.status
        ))
        return result

    def save_user(self, user):
        """
        Save the current user obj
        """
        query = '''
        UPDATE
            users
        SET
            email=%s, password_hash=%s, password_salt=%s, status=%s, password_reset=%s, reset_link=%s
        WHERE
            id=%s
        '''
        result = self.execute_query(query, (
            user.email, user.password_hash, user.password_salt, user.status, user.password_reset,
            user.reset_link, user.id
        ))
        return result

    def get_user_by_email(self, email):
        """
        Select user by email, used for login
        """
        query = '''SELECT * FROM users WHERE email=%s'''
        result = self.fetch_one(query, (email,))
        return result

    def get_user_by_id_simple(self, user_id):
        """
        Select user by id, without the JOINED permissions.
        """
        query = '''SELECT * FROM users WHERE id=%s'''
        result = self.fetch_one(query, (user_id, ))
        return result

    def get_user_by_id(self, user_id):
        """
        Select user by id, used for authenticating requests, mainly.
        """
        query = '''SELECT * FROM users INNER JOIN permissions ON permissions.user_id = users.id WHERE id=%s'''
        result = self.fetch_one(query, (user_id,))
        return result

    def create_website(self, website):
        """
        Insert a new website entry
        """
        query = '''
        INSERT INTO
            websites (url, ip_address, hidden_domain, status, hash_id, creator_id, awstats_password)
        VALUES
            (%s,%s,%s,%s,%s,%s,%s)'''

        result = self.execute_query(query, (
            website.url,
            website.ip_address,
            website.hidden_domain,
            website.status,
            website.hash_id,
            website.creator_id,
            website.awstats_password
        ))
        return result

    def create_permission(self, permission):
        """
        Insert a new permission entry
        """
        query = '''INSERT INTO permissions (user_id, website_id, role) VALUES (%s, %s, %s)'''
        result = self.execute_query(query, (
            permission.user_id, permission.website_id, permission.role
        ))
        return result

    def delete_permission(self, website, user_id_to_delete):
        """
        Delete a permission for a given website.
        """
        query = '''DELETE FROM permissions WHERE website_id=%s AND user_id=%s'''
        result = self.execute_query(query, (website.id, user_id_to_delete))
        return result

    def get_websites(self):
        """
        Fetch all websites which the current user has permission to see/edit.
        """
        query = '''SELECT * FROM websites INNER JOIN permissions ON websites.id = permissions.website_id WHERE
            permissions.user_id=%s'''
        result = self.fetch_all(query, (current_user.id,))
        return result

    def get_website_by_hash(self, hash_id):
        """
        Get one specific website by hash id. Make sure the current user is allowed to access it.
        """
        hash_bin = binascii.unhexlify(hash_id)
        query = '''SELECT * FROM websites INNER JOIN permissions ON websites.id = permissions.website_id
        WHERE websites.hash_id=%s AND permissions.user_id=%s'''
        result = self.fetch_one(query, (hash_bin, current_user.id, ))
        return result

    def get_website_by_id(self, website_id):
        """
        Fetch a single website by its id
        """
        query = '''SELECT * FROM websites WHERE id=%s'''
        result = self.fetch_one(query, (website_id,))
        return result

    def save_website(self, website):
        """
        Save a full website object
        """
        query = '''
        UPDATE
            websites
        SET
            url=%s, status=%s, ip_address=%s, banjax_auth_hash=%s, admin_key=%s,
            save_visitor_logs=%s, use_ssl=%s, ssl_certificate_file_upload_date=%s, ssl_key_file_upload_date=%s,
            ssl_chain_file_upload_date=%s, cache_time=%s, under_attack=%s
        WHERE
            id=%s
        '''
        result = self.execute_query(query, (
            website.url,
            website.status,
            website.ip_address,
            website.banjax_auth_hash,
            website.admin_key,
            website.save_visitor_logs,
            website.use_ssl,
            website.ssl_certificate_file_upload_date,
            website.ssl_key_file_upload_date,
            website.ssl_chain_file_upload_date,
            website.cache_time,
            website.under_attack,
            website.id
        ))
        return result

    def get_users_by_website_hash_id(self, hash_id):
        """
        Get all users allowed to see a particular website
        """
        hash_bin = binascii.unhexlify(hash_id)
        query = '''SELECT p.user_id, p.role, u.email, u.status FROM permissions p INNER JOIN websites ON websites.id =
        p.website_id JOIN users u ON u.id = p.user_id WHERE websites.hash_id=%s'''
        result = self.fetch_all(query, (hash_bin,))
        return result

    def save_record(self, record):
        query = """
        UPDATE records SET
            weight=%s,
            hostname=%s,
            value=%s,
            priority=%s,
            deflect=%s,
            type=%s
        WHERE
            id=%s
        """
        result = self.execute_query(query, (
            record['weight'],
            record['hostname'],
            record['value'],
            record['priority'],
            record['deflect'],
            record['type'],
            record['id']
            )
        )
        return result

    def save_records_list(self, records):
        """
        Save DNS zone file records to records table. If a duplicate unique key is found, update it.
        """
        query = '''
        INSERT INTO
            records (website_id, type, hostname, value, priority, deflect, weight, port)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            type=VALUES(type),
            hostname=VALUES(hostname),
            value=VALUES(value),
            priority=VALUES(priority),
            website_id=VALUES(website_id),
            deflect=VALUES(deflect),
            weight=VALUES(weight),
            port=VALUES(port)
        '''
        result = self.execute_many(query, records)
        return result

    def get_records_for_website(self, hash_id):
        """
        Fetch all the records for a hash_id, given that you are allowed to access them (permissions).
        First select the website, grab its ID, join the permissions, and finally join the records data.
        """
        hash_bin = binascii.unhexlify(hash_id)
        query = '''
        SELECT
            websites.hash_id as website_hash_id,
            websites.id as website_id,
            permissions.website_id,
            permissions.user_id as permissions_user_id,
            records.type,
            records.hostname,
            records.value,
            records.priority,
            records.weight,
            records.port,
            records.id,
            records.deflect
        FROM
            websites
        LEFT JOIN
            permissions ON permissions.website_id=websites.id
        LEFT JOIN
            records ON records.website_id=permissions.website_id
        WHERE
            websites.hash_id=%s
        AND
            permissions.user_id=%s
        ORDER BY
            records.type, records.hostname
        '''
        result = self.fetch_all(query, (hash_bin, current_user.id))
        return result

    def delete_record(self, record_id):
        """
        Delete a DNS zone file record for a website. Make sure the current logged in user actually has
        permission to do this first.
        """
        query = '''
        SELECT
            records.id,
            records.website_id,
            permissions.website_id,
            permissions.user_id
        FROM
            records
        LEFT JOIN
            permissions ON permissions.website_id=records.website_id
        WHERE
            records.id=%s
        '''
        result = self.fetch_one(query, (record_id,))
        if not result or 'user_id' not in result or result['user_id'] != current_user.id:
            return None, ___("Could not delete the DNS record.")
        query = '''DELETE FROM records WHERE id=%s'''
        result = self.execute_query(query, (record_id, ))
        return result, None

    def add_record(self, args):
        """
        Add a record to the users' website
        """
        record_type, hostname, value, priority, weight, port, deflect, website_id = args
        query = '''SELECT * FROM permissions WHERE user_id=%s AND website_id=%s'''
        result = self.fetch_one(query, (current_user.id, website_id))
        if not result:
            return None, "Could not add this record."
        try:
            query = '''INSERT INTO records (type, hostname, value, priority, weight, port, website_id, deflect) VALUES
             (%s, %s, %s, %s, %s, %s, %s, %s)'''
            result = self.execute_query(query, (
                record_type, hostname, value, priority, weight, port, website_id, deflect)
            )
            return result, None
        except MySQLdb.IntegrityError:
            logging.error("This record already exists")
            return None, ___("This record already exists.")

    def update_website_ns_info(self, nsinfo, website_id):
        """
        easydns hosting has been bought, inform the user about it and send them an email
        """
        query = '''UPDATE websites SET nsinfo=%s, status=3 WHERE id=%s'''
        result = self.execute_query(query, (nsinfo, website_id, ))
        return result

    def lock_website(self, website):
        """
        Shortcut to locking website. We need this for the threading call, which is outside of the main application
        context.
        """
        try:
            self.execute_query('''UPDATE websites SET scan_in_progress=1 WHERE id=%s''', (website.id, ))
        except AttributeError:
            logging.info("Could not lock website")

    def unlock_website(self, website):
        """
        Unlock the website
        """
        self.execute_query('''UPDATE websites SET scan_in_progress=0 WHERE id=%s''', (website.id, ))

    def get_website_by_url(self, url):
        """
        Get a website by its URL
        """
        result = self.fetch_one('''SELECT * FROM websites WHERE url=%s''', (url, ))
        return result

    def wipe_all_records_for_website(self, website_id):
        return self.execute_query('''DELETE FROM records WHERE website_id=%s''', (website_id, ))

    def delete_website_simple(self, hash_id):
        """
        Delete a website before it was setup (simple). Make sure we are 100% certain this is the creator_id's website
        by using the 'current_user' obj.
        """
        hash_bin = binascii.unhexlify(hash_id)
        query = '''DELETE FROM websites WHERE hash_id=%s AND creator_id=%s'''
        result = self.execute_query(query, (hash_bin, current_user.id, ))
        return result

    """
    Admin-related calls.
    """

    def get_all_websites(self):
        query = '''SELECT id, url, status, creator_id, ip_address FROM websites ORDER BY url ASC'''
        return self.fetch_all(query)

    def get_website_records(self, website_id):
        query = '''SELECT * FROM records WHERE website_id=%s'''
        return self.fetch_all(query, (website_id, ))

    def edit_website_data(self, website_id, field, value):
        query = '''UPDATE websites SET {}=%s WHERE id=%s'''.format(field)
        return self.execute_query(query, (value, website_id))

    def update_website_ns_changed(self, website_id):
        query = '''UPDATE websites SET status=4 WHERE id=%s'''
        return self.execute_query(query, (website_id, ))

    def update_website_final_step(self, website_id):
        query = '''UPDATE websites SET status=-1 WHERE id=%s'''
        return self.execute_query(query, (website_id, ))

    def get_user_by_reset_link(self, hash_id):
        query = '''SELECT * FROM users WHERE reset_link=%s'''
        return self.fetch_one(query, (hash_id, ))

    def reset_website_setup_to_zero(self, website_id):
        query = '''UPDATE websites SET status=0, scan_in_progress=0 WHERE id=%s'''
        return self.execute_query(query, (website_id, ))

    def delete_website_by_id(self, website_id):
        query = '''DELETE FROM websites WHERE id=%s'''
        return self.execute_query(query, (website_id, ))

    def delete_permissions_for_website(self, website_id):
        query = '''DELETE FROM permissions WHERE website_id=%s'''
        return self.execute_query(query, (website_id, ))

    def delete_records_for_website(self, website_id):
        query = '''DELETE FROM records WHERE website_id=%s'''
        return self.execute_query(query, (website_id, ))

    def delete_user(self, user_id):
        query = '''DELETE FROM users WHERE id=%s'''
        return self.execute_query(query, (user_id, ))

    def get_users(self):
        query = '''
        SELECT
            users.id, users.status, users.date_joined, users.email,
            websites.url
        FROM
            users
        LEFT JOIN
            websites
        ON
            websites.creator_id = users.id
        '''
        return self.fetch_all(query, None)
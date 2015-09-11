Distributed Deflect Volunteer frontend and admin
===============

**Overview of data flow**

- Step 0: USER: User has added Server to dashboard (IP, Port), setup not started.
- Step 1: USER: Adds server settings(optional:{time of day start, time of day end availability, total bandwidth - zero being unlimited).
- Step 3: USER: Follow install guide, confirm when install up and running.
- Step 4: ADMIN: Test Volunteer edge in test network, move to next step if passed.
- Step 5: ADMIN: Update User about use or issues for server.
- Step 6: ADMIN: Volunteer Edge enters full rotation
- Step -1: USER: Setup is done, redirected to stats


**To run the frontend repo you need:**

- python 2.7
- python-pip
- libmysqlclient-dev
- python-dev
- libffi-dev (`[sudo] apt-get install libffi-dev`)
- python-dnspython

**First install the requirements using pip:**

- `[sudo] pip install -r requirements.txt`


**Configuration:**

- Make sure to set the `SERVER_ENV` variable to either `DEV`, `STAGING`, `PRODUCTION`
- If you are running the repo locally, rename `/instance/config-sample.py` to `/instance/config.py` and
change values according to the `SERVER_ENV` variable.
- Make sure to override the default `ADMIN_USER` and `ADMIN_PASSWORD` for the admin app

**Generate GPG keys**
```
cd instance
python genkeys.py
cd ..
```

**Import the latest schema in /config/sql/schema.sql:**
- `mysql -u user -p my_db < eq-dashboard.sql`

**Run the thing:**

- `python run_frontend.py`
- `python run_admin.py`
- The frontend and admin apps share login manager code, you cannot be logged in to the admin and
the frontend simultaneously. Every request is checked for authentication, so the app has to choose whether you are
logged into the frontend or the admin. There is a special user with an ID of `0` for the admin, not present in the DB.

**Translating notes:**

The usual flow will go as following:

- Add a new multilang string by using the `_()` or lazy `___()` methods
- `cd` into `config/babel` and run `./extract.sh` to grab the new translatable strings
- run `./update.sh` to update you individual translation files with the new strings from the `messages.pot` template
- translate your files in `frontend/translations/<LANG>/LC_MESSAGES/messages.po`
- run `./compile.sh` to compile into `.mo` files to be used on the frontend.
- add the language prefix to `allowed_langs` in `/views/lang.py`

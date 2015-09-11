#!/usr/bin/env python

from admin import app
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

# database instance
import lib.DB as DB
app.db = DB.DB(app.config["DB_HOST"], app.config["DB_USER"], app.config["DB_PASS"], app.config["DB_NAME"])

app.run(
    host=app.config["ADMIN_HOST_IP"],
    port=app.config["ADMIN_PORT"]
)

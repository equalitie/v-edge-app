import gnupg
import getpass
import config

user_pass = getpass.getpass("Please enter your passphrase: ")

print "Configuring your GPG home folder."
gpg = gnupg.GPG(gnupghome=config.GPGHOME)

print "Setting user and passphrase."
input_data = gpg.gen_key_input(name_email=config.GPG_EMAIL, passphrase=user_pass)

print "Generating keys, this might take a while... " \
      "(more info here: https://pythonhosted.org/python-gnupg/#performance-issues) "
key = gpg.gen_key(input_data)

print "Key id: {}".format(key)

print "Exporting public keys."
ascii_armored_public_keys = gpg.export_keys(str(key))

print "Exporting private keys."
ascii_armored_private_keys = gpg.export_keys(str(key), True)

print "Writing to keyfile.asc."
with open('keyfile.asc', 'w') as f:
    f.write(ascii_armored_public_keys)
    f.write(ascii_armored_private_keys)

print "Done."

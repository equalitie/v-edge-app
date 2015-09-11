class CannotParseDNSZoneFile(Exception):
    pass


class NoZoneFileExists(Exception):
    pass


class InvalidWebsite(Exception):
    pass


class WebsiteNeedsSetup(Exception):
    pass


class UserNeedsToChangePassword(Exception):
    pass


class WrongSetupStep(Exception):
    pass


class SiteSetupDone(Exception):
    pass
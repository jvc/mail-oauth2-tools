# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

# Map of hostnames to [issuer, scope].
host_config = {
    "imap.googlemail.com": ["accounts.google.com", "https://mail.google.com/"],
    "smtp.googlemail.com": ["accounts.google.com", "https://mail.google.com/"],
    "pop.googlemail.com": ["accounts.google.com", "https://mail.google.com/"],
    "imap.gmail.com": ["accounts.google.com", "https://mail.google.com/"],
    "smtp.gmail.com": ["accounts.google.com", "https://mail.google.com/"],
    "pop.gmail.com": ["accounts.google.com", "https://mail.google.com/"],

    "imap.mail.ru": ["o2.mail.ru", "mail.imap"],
    "smtp.mail.ru": ["o2.mail.ru", "mail.imap"],

    "imap.yandex.com": ["oauth.yandex.com", "mail:imap_full"],
    "smtp.yandex.com": ["oauth.yandex.com", "mail:smtp"],

    "imap.mail.yahoo.com": ["login.yahoo.com", "mail-w"],
    "pop.mail.yahoo.com": ["login.yahoo.com", "mail-w"],
    "smtp.mail.yahoo.com": ["login.yahoo.com", "mail-w"],

    "imap.aol.com": ["login.aol.com", "mail-w"],
    "pop.aol.com": ["login.aol.com", "mail-w"],
    "smtp.aol.com": ["login.aol.com", "mail-w"],

    "outlook.office365.com":
    [
        "login.microsoftonline.com",
        "https://outlook.office365.com/IMAP.AccessAsUser.All https://outlook.office365.com/POP.AccessAsUser.All https://outlook.office365.com/SMTP.Send offline_access",
    ],
    "smtp.office365.com":
    [
        "login.microsoftonline.com",
        "https://outlook.office365.com/IMAP.AccessAsUser.All https://outlook.office365.com/POP.AccessAsUser.All https://outlook.office365.com/SMTP.Send offline_access",
    ],
}

# Map of issuers to authorizationEndpoint, tokenEndpoint. Issuer is a unique
# string for the organization that your application/client is registered at.
issuer_eps = {
    "accounts.google.com":
    [
        "https://accounts.google.com/o/oauth2/auth",
        "https://www.googleapis.com/oauth2/v3/token",
    ],
    "o2.mail.ru":
    [
        "https://o2.mail.ru/login",
        "https://o2.mail.ru/token",
    ],
    "oauth.yandex.com":
    [
        "https://oauth.yandex.com/authorize",
        "https://oauth.yandex.com/token",
    ],
    "login.yahoo.com":
    [
        "https://api.login.yahoo.com/oauth2/request_auth",
        "https://api.login.yahoo.com/oauth2/get_token",
    ],
    "login.aol.com":
    [
        "https://api.login.aol.com/oauth2/request_auth",
        "https://api.login.aol.com/oauth2/get_token",
    ],
    "login.microsoftonline.com":
    [
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    ],
}


class ProviderLookupError(LookupError):
    pass


def get_hosts():
    """
    Return list of supported provider host names.
    """
    return host_config.keys()


def get_host_config(host):
    """
    Return the configuration of a host. This is (issuer, scope)
    """
    try:
        return host_config[host]
    except KeyError:
        raise ProviderLookupError("Unknown host: %s" % (host))


def get_issuer_eps(issuer):
    """
    Return (auth_endpoint, token_endpoint)
    """
    try:
        return issuer_eps[issuer]
    except KeyError:
        raise ProviderLookupError("Unknown issuer: %s" % (issuer))


def main():
    """
    Print all information to stdout.
    """
    for host in get_hosts():
        (issuer, scope) = get_host_config(host)
        (auth_ep, tok_ep) = get_issuer_eps(issuer)

        print "%s" % (host)
        print "  Issuer: ",
        print issuer
        print "   Scope: ",
        print scope
        print " Auth EP: ",
        print auth_ep
        print "Token EP: ",
        print tok_ep
        print


if __name__ == "__main__":
    main()

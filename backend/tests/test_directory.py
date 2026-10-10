import pytest
from pydantic import ValidationError

from app.api.admin_directory import LdapIn, OidcIn


def test_oidc_settings_validation():
    ok = OidcIn(enabled=True, issuer="https://idp.example.org/realms/corp", client_id="lsx")
    assert ok.scopes == "openid profile email"
    with pytest.raises(ValidationError):
        OidcIn(enabled=True, issuer="", client_id="lsx")  # enabling needs an issuer
    with pytest.raises(ValidationError):
        OidcIn(enabled=False, issuer="https://idp.example.org", scopes="profile email")  # openid is mandatory
    with pytest.raises(ValidationError):
        OidcIn(enabled=True, issuer="http://idp.example.org", client_id="lsx")  # https outside development


def test_ldap_settings_validation():
    ok = LdapIn(enabled=True, url="ldaps://dc01.corp.local:636", bind_dn="CN=svc,DC=corp", user_base="DC=corp")
    assert ok.group_attribute == "memberOf"
    with pytest.raises(ValidationError):
        LdapIn(enabled=False, url="ldap://dc01.corp.local")  # TLS is mandatory
    with pytest.raises(ValidationError):
        LdapIn(enabled=True, url="ldaps://dc01", bind_dn="CN=svc", user_base="DC=corp", user_filter="(uid=x)")
    with pytest.raises(ValidationError):
        LdapIn(enabled=True, url="ldaps://dc01", bind_dn="", user_base="DC=corp")

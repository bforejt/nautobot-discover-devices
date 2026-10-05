"""Device Secrets Group credentials, adapted from nautobot-testsuite/creds.py.

The upstream access-type cascade is retained; provider error text and chained
exceptions are deliberately suppressed because they can contain secret values.
"""


class CredentialsError(RuntimeError):
    """Credentials could not be resolved; message is safe for a JobResult."""


def resolve_credentials(device, override_group=None, *, transport="restconf"):
    """Resolve a transport-specific username/password from the selected Secrets Group."""
    from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
    from nautobot.extras.models.secrets import SecretsGroupAssociation

    try:
        from billiard.exceptions import SoftTimeLimitExceeded

        cancellation_errors = (SoftTimeLimitExceeded,)
    except ImportError:
        cancellation_errors = ()

    if transport not in ("restconf", "ssh"):
        raise CredentialsError("Unsupported discovery credential transport")
    names = (
        ("TYPE_SSH", "TYPE_GENERIC")
        if transport == "ssh"
        else ("TYPE_RESTCONF", "TYPE_HTTP", "TYPE_REST", "TYPE_GENERIC")
    )
    access_description = (
        "SSH or Generic" if transport == "ssh" else "RESTCONF, HTTP, REST or Generic"
    )
    group = override_group if override_group is not None else device.secrets_group
    if group is None:
        raise CredentialsError(
            "The selected device has no Secrets Group and no override was provided"
        )
    access_types = []
    for name in names:
        access_type = getattr(SecretsGroupAccessTypeChoices, name, None)
        if access_type is not None and access_type not in access_types:
            access_types.append(access_type)

    def lookup(secret_type):
        for access_type in access_types:
            try:
                return group.get_secret_value(
                    access_type=access_type, secret_type=secret_type, obj=device
                )
            except SecretsGroupAssociation.DoesNotExist:
                continue
            except cancellation_errors:
                raise
            except Exception:
                raise CredentialsError(
                    "Secrets Group provider failed resolving %s/%s; "
                    "check the provider configuration" % (access_type, secret_type)
                ) from None
        return None

    username = lookup(SecretsGroupSecretTypeChoices.TYPE_USERNAME)
    password = lookup(SecretsGroupSecretTypeChoices.TYPE_PASSWORD)
    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(password, str)
        or not password
    ):
        raise CredentialsError(
            "Secrets Group has no usable username/password for %s access" % access_description
        )
    return username, password

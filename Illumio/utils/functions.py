from illumio import PolicyComputeEngine

from .config import IllumioPluginConfig


def parse_label_scope(scope: str) -> dict:
    """Parses label scopes passed as a string of the form k1:v1,k2:v2,...

    Args:
        scope (str): Policy scope as a comma-separated key:value pair list.

    Returns:
        dict: dict containing label key:value pairs.
    """
    label_dimensions = scope.split(",")
    labels = {}
    for label in label_dimensions:
        k, v = label.split(":")
        labels[k] = v
    return labels


def connect_to_pce(conf: IllumioPluginConfig, proxies: dict = None) -> PolicyComputeEngine:
    """Connect to the PCE, returning the PolicyComputeEngine client.

    Args:
        conf (dict): dict containing plugin configuration values.

    Returns:
        PolicyComputeEngine: PCE API client object.

    Raises:
        IllumioException: if the PCE connection fails.
    """
    pce = PolicyComputeEngine(conf.pce_url, port=conf.pce_port, org_id=conf.org_id)
    pce.set_credentials(conf.api_username, conf.api_secret)
    if proxies:
        pce.set_proxies(http_proxy=proxies['http'], https_proxy=proxies['https'])
    pce.must_connect()
    return pce


__all__ = [
    "parse_label_scope",
    "connect_to_pce",
]
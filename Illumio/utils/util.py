import illumio

def parse_label_scope(scope: str) -> dict:
    """Parses label scopes passed as a string of the form k1:v1,k2:v2,..."""
    label_dimensions = scope.split(",")
    labels = {}
    for label in label_dimensions:
        k, v = label.split(":")
        labels[k] = v
    return labels

def connect_to_pce(config: dict) -> illumio.PolicyComputeEngine:
    """Connect to the PCE, returning the PolicyComputeEngine client

    Args:
        config (dict): dict containing plugin configuration values

    Raises:
        IllumioException: if the PCE connection fails
    """
    pce = illumio.PolicyComputeEngine(config["api_url"], port=config["api_port"], org_id=config["org_id"])
    pce.set_credentials(config["api_username"], config["api_password"])
    pce.must_connect()
    return pce

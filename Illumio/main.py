# -*- coding: utf-8 -*-

"""This module provides the Illumio plugin for Netskope Threat Exchange.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
import json
import traceback
from typing import List

from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult

from illumio import PolicyComputeEngine

from .utils import IllumioPluginConfig, parse_label_scope, connect_to_pce

PLUGIN_NAME = "CTE Illumio Plugin"


class IllumioPlugin(PluginBase):
    """Netskope Threat Exchange plugin for the Illumio PCE.

    Retrieves threat IoCs from Illumio based on a provided policy scope.
    """

    pce: PolicyComputeEngine

    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
        self.log_prefix = f"{PLUGIN_NAME} [{name}]"

    def pull(self):
        """Pull workloads matching the configured scope from the Illumio PCE.

        Queries the PCE based on the given label scope, creating threat
        indicators for each interface on workloads matching the scope.
        """
        try:
            conf = IllumioPluginConfig(**self.configuration)
            self.pce = connect_to_pce(
                conf, proxies=self.proxy, verify=self.ssl_validation
            )

            indicators = []

            ips = self.get_threat_indicators(conf.label_scope)
            for ip in ips:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully retrieved IP: {ip}"
                )
                indicators.append(Indicator(value=ip, type=IndicatorType.URL))
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Failed to pull threat IoCs: {str(e)}",
                details=traceback.format_exc()
            )

        return indicators

    def get_threat_indicators(self, label_scope: str) -> List[str]:
        """Retrieve threat workload IPs from the Illumio PCE.

        Given a PCE connection client and policy scope, we call the PCE APIs to
        get workloads matching the scope and return all interface IP addresses.

        Args:
            pce (PolicyComputeEngine): PCE API client object.
            label_scope (string): Policy scope as a comma-separated key:value
                pair list.

        Returns:
            List[str]: List of IP addresses from threat workloads.
        """
        refs = []

        try:
            labels = parse_label_scope(label_scope)

            for key, value in labels.items():
                labels = self.pce.labels.get(
                    params={"key": key, "value": value}
                )
                if len(labels) > 0:
                    # only expect to match a single label for each k:v pair
                    refs.append(labels[0].href)
                else:
                    self.logger.warn(
                        f'{self.log_prefix}: Failed to find label with'
                        f' key "{key}" and value "{value}"'
                    )

            workloads = self.pce.workloads.get_async(
                params={'labels': json.dumps([refs])}
            )
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Failed to fetch workloads: {str(e)}"
            )

        ips = []

        for workload in workloads:
            for interface in workload.interfaces:
                if interface.address:
                    ips.append(str(interface.address))

        return ips

    def validate(self, configuration):
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        self.logger.info("{self.log_prefix}: validating plugin instance")

        # read the configuration into a dataclass - type checking is performed
        # as a post-init on all fields. Implicitly checks existence, where the
        # TypeError falls through to the catch-all Exception case
        try:
            conf = IllumioPluginConfig(**configuration)
        except ValueError as e:
            self.logger.error(
                f"{self.log_prefix}: {str(e)}",
                details=traceback.format_exc()
            )
            return ValidationResult(success=False, message=str(e))
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Failed to read config: {str(e)}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Missing one or more configuration parameters"
            )

        error_message = ""

        if not conf.pce_url.strip():
            error_message = "PCE URL cannot be empty"
        elif not conf.api_username.strip():
            error_message = "API Username cannot be empty"
        elif not conf.api_secret.strip():
            error_message = "API Secret cannot be empty"
        elif conf.org_id <= 0:
            error_message = "Org ID must be a positive integer"
        elif not (1 <= conf.pce_port <= 65535):
            error_message = "PCE Port must be an integer in the range 1-65535"
        elif not conf.label_scope.strip():
            error_message = "Label Scope cannot be empty"
        else:
            try:
                parse_label_scope(conf.label_scope)
            except Exception as e:
                error_message = f"Failed to parse Label Scope: {str(e)}"

        # only try to connect if the configuration is valid
        if not error_message:
            try:
                connect_to_pce(
                    conf, proxies=self.proxy, verify=self.ssl_validation
                )
            except Exception as e:
                error_message = f"Unable to connect to PCE: {str(e)}"

        error_message = error_message.strip()

        if error_message:
            self.logger.error(
                f"{self.log_prefix}: Validation error: {error_message}",
                details=traceback.format_exc()
            )

        return ValidationResult(
            success=error_message == "",
            message=error_message or "Validation successful"
        )

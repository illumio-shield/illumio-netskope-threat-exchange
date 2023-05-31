"""Illumio Plugin providing implementation for pull and validate methods from PluginBase."""
import json
import os
import sys
from typing import List

from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult
)
from pydantic import ValidationError

root_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(root_dir, "lib"))

from illumio import PolicyComputeEngine, IllumioException

from .utils import IllumioPluginConfig, parse_label_scope, connect_to_pce


class IllumioPlugin(PluginBase):
    """IllumioPlugin class containing concrete """

    def pull(self):
        """Pull workloads matching the configured scope from the Illumio PCE.

        Queries the PCE based on the given label scope, creating threat
        indicators for each interface on workloads matching the scope.
        """
        conf = IllumioPluginConfig(**self.configuration)
        pce = connect_to_pce(conf, proxies=self.proxy)

        indicators = []
        ips = self.get_threat_indicators(pce, conf.label_scope)
        for ip in ips:
            indicators.append(Indicator(value=ip, type=IndicatorType.URL))
            self.logger.info(f"Illumio Plugin: Successfully retrieved IP: {ip}")

        return indicators

    def get_threat_indicators(self, pce: PolicyComputeEngine, label_scope: str) -> List[str]:
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
        labels = parse_label_scope(label_scope)

        refs = []
        ips = []

        try:
            for key, value in labels.items():
                labels = pce.labels.get(params={"key": key, "value": value})
                if len(labels) > 0:
                    refs.append(labels[0].href)

            workloads = pce.workloads.get_async(params={'labels': json.dumps([refs])})
        except IllumioException as e:
            self.logger.error(f"Illumio Plugin: Failed to fetch workloads: {str(e)}")

        for workload in workloads:
            for interface in workload.interfaces:
                try:
                    self.logger.debug(f"Illumio Plugin: Successfully retrieved IP: {str(interface.address)}")
                    ips.append(interface.address)
                except ValidationError as err:
                    self.logger.warn(f"Illumio Plugin: Skipping workload {workload.hostname}: error encountered reading interfaces")

        return ips

    def validate(self, configuration):
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        self.logger.info("Illumio Plugin: validating plugin instance")

        # read the configuration into a dataclass - type checking is performed
        # as a post-init on all fields. Implicitly checks existence, where the
        # TypeError falls through to the catch-all Exception case
        try:
            conf = IllumioPluginConfig(**configuration)
        except ValueError as e:
            self.logger.error(f"Illumio Plugin: {str(e)}")
            return ValidationResult(success=False, message=str(e))
        except Exception as e:
            self.logger.error(f"Illumio Plugin: Failed to read config: {str(e)}")
            return ValidationResult(success=False, message="Missing one or more configuration parameters")

        error_message = ""

        if not conf.pce_url:
            error_message = "PCE URL cannot be empty"
        elif not conf.api_username:
            error_message = "API Username cannot be empty"
        elif not conf.api_secret:
            error_message = "API Secret cannot be empty"
        elif conf.org_id <= 0:
            error_message = "Org ID must be a positive integer"
        elif not (1 <= conf.pce_port <= 65535):
            error_message = "PCE Port must be an integer in the range 1 - 65535"
        elif not conf.label_scope:
            error_message = "Label Scope cannot be empty"
        else:
            try:
                parse_label_scope(conf.label_scope)
            except Exception as e:
                error_message = f"Failed to parse Label Scope: {str(e)}"

        # only try to connect if the configuration is valid
        if not error_message:
            try:
                connect_to_pce(conf, proxies=self.proxy)
            except Exception as e:
                error_message = f"Unable to connect to PCE: {str(e)}"

        error_message = error_message.strip()

        if error_message:
            self.logger.error(f"Illumio Plugin: One or more validation errors occurred: {error_message}")

        return ValidationResult(
            success=error_message == "",
            message=error_message or "Validation successful"
        )

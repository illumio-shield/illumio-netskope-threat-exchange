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

PLUGIN_NAME = "Illumio CTE Plugin"


class IllumioPlugin(PluginBase):
    """Netskope Threat Exchange plugin for the Illumio PCE.

    Retrieves threat IoCs from Illumio based on a provided policy scope.
    """

    pce: PolicyComputeEngine

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

            return self._get_threat_indicators(conf.label_scope)
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Failed to pull threat IoCs: {str(e)}",
                details=traceback.format_exc()
            )

        return indicators

    def _get_threat_indicators(self, label_scope: str) -> List[Indicator]:
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
        try:
            refs = self._get_label_refs(parse_label_scope(label_scope))
            workloads = self.pce.workloads.get_async(
                # the labels query param takes a JSON-formatted nested list of
                # label HREFs - each inner list represents a separate scope
                params={'labels': json.dumps([refs])}
            )
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Failed to fetch workloads: {str(e)}"
            )

        indicators = []

        for workload in workloads:
            workload_id = workload.href.split('/')[-1]
            pce_url = "{}://{}:{}".format(
                self.pce._scheme, self.pce._hostname, self.pce.port
            )
            workload_uri = f'{pce_url}/#/workloads/{workload_id}'
            desc = f'Illumio Workload - {workload.name}' \
                f'\n{workload.description}'

            if workload.hostname:
                indicators.append(
                    Indicator(
                        value=workload.hostname,
                        type=IndicatorType.URL,
                        comments=desc,
                        extendedInformation=workload_uri
                    )
                )

            for interface in workload.interfaces:
                if interface.address:
                    indicators.append(
                        Indicator(
                            value=str(interface.address),
                            type=IndicatorType.URL,
                            comments=desc,
                            extendedInformation=workload_uri
                        )
                    )

        self.logger.info(
            f"{PLUGIN_NAME}: Successfully retrieved {len(indicators)} IoCs"
        )

        return indicators

    def _get_label_refs(self, labels: dict) -> List[str]:
        """Retrieve Label object HREFs from the PCE.

        Args:
            labels (dict): label key:value pairs to look up.

        Returns:
            List[str]: List of HREFs.
        """
        refs = []

        for key, value in labels.items():
            labels = self.pce.labels.get(
                params={"key": key, "value": value}
            )
            if len(labels) > 0:
                # only expect to match a single label for each k:v pair
                refs.append(labels[0].href)
            else:
                msg = f'{PLUGIN_NAME}: Failed to find label with' \
                    f' key "{key}" and value "{value}"'
                self.logger.warn(f'{PLUGIN_NAME}: {msg}')
                self.notifier.warn(f'{PLUGIN_NAME}: {msg}')

        return refs

    def validate(self, configuration):
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        self.logger.info(f"{PLUGIN_NAME}: validating plugin instance")

        # read the configuration into a dataclass - type checking is performed
        # as a post-init on all fields. Implicitly checks existence, where the
        # TypeError falls through to the catch-all Exception case
        try:
            conf = IllumioPluginConfig(**configuration)
        except ValueError as e:
            self.logger.error(
                f"{PLUGIN_NAME}: {str(e)}",
                details=traceback.format_exc()
            )
            return ValidationResult(success=False, message=str(e))
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Failed to read config: {str(e)}",
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
                    conf, proxies=self.proxy, verify=self.ssl_validation,
                    # fail quickly if PCE connection params are invalid
                    retry_count=1, request_timeout=5
                )
            except Exception as e:
                error_message = f"Unable to connect to PCE: {str(e)}"

        error_message = error_message.strip()

        if error_message:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error: {error_message}",
                details=traceback.format_exc()
            )

        return ValidationResult(
            success=error_message == "",
            message=error_message or f"{PLUGIN_NAME}: Validation successful"
        )

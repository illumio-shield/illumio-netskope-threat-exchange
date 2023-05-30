"""Illumio Plugin providing implementation for pull and validate methods from PluginBase."""
import json
import os
import sys

import requests
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.plugin_base import (PluginBase, PushResult,
                                                   ValidationResult)
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from illumio import PolicyComputeEngine
from utils import *


class IllumioPlugin(PluginBase):
    def handle_error(self, resp: requests.Response) -> any:
        try:
            resp.raise_for_status()
            return resp.json()
        except ValueError as e:
            raise Exception(f"Illumio Plugin: failed to parse JSON: {str(e)}") from e
        except Exception as e:
            raise Exception(f"Illumio Plugin: Exception {str(e)}") from e

    def get_threat_indicators(self, pce, label_scope):
        labels = parse_label_scope(label_scope)

        refs = []
        ips = []

        for key, value in labels.items():
            labels = pce.labels.get(params={"key": key, "value": value})
            if len(labels) > 0:
                refs.append(labels[0].href)

        workloads = pce.workloads.get_async(params={'labels': json.dumps([refs])})

        for workload in workloads:
            for interface in workload.interfaces:
                try:
                    self.logger.info("Illumio Plugin Successfully retrieved IP: " + str(interface.address))
                    ips.append(interface.address)
                except ValidationError as err:
                    self.logger.info(f"Skipping workload {workload.hostname}: error encountered reading interfaces")

        return ips

    def pull(self):
        """Pull IPs of desired Labels from PCE
        Get all content from location configured on the plugin"""
        config = self.configuration

        pce = connect_to_pce(config)

        indicators = []
        ips = self.get_threat_indicators(pce, config["label_scope"])
        for ip in ips:
            indicators.append(Indicator(value=ip, type=IndicatorType.URL))
            self.logger.info(f"Illumio Plugin: Successfully retrieved IP: {ip}")
        return indicators


    def validate(self, data):
        """Validate the Plugin configuration parameters.
        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the cte.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info("Illumio Plugin: validating plugin instance")

        success = True
        message = "Validation successful"

        if "api_url" not in data or not isinstance(data["api_url"], str) or not data["api_url"]:
            success = False
            message = "Missing or invalid PCE URL"
        elif "api_username" not in data or not isinstance(data["api_username"], str) or not data["api_username"]:
            success = False
            message = "Missing or invalid API Username"
        elif "api_password" not in data or not isinstance(data["api_password"], str) or not data["api_password"]:
            success = False
            message = "Missing or invalid API Secret"
        elif "org_id" not in data or not isinstance(data["org_id"], int) or not data["org_id"]:
            success = False
            message = "Missing or invalid Org ID"
        elif "api_port" not in data or not isinstance(data["api_port"], int) or not data["api_port"]:
            success = False
            message = "Missing or invalid API port"
        elif "label_scope" not in data or not isinstance(data["label_scope"], str) or not data["label_scope"]:
            success = False
            message = "Missing or invalid Label Scope"
        else:
            # FIXME: put this in its own block; this flow in general should be refactored
            try:
                parse_label_scope(data["label_scope"])
            except Exception as e:
                success = False
                message = "Failed to parse Label Scope: " + str(e)

            try:
                connect_to_pce(data)
            except Exception as e:
                success = False
                message = "Unable to connect to PCE: " + str(e)

        if not success:
            self.logger.error(f"Illumio Plugin - validation error: {message}")
        return ValidationResult(success=success, message=message)

"""Illumio Plugin providing implementation for pull and validate methods from PluginBase."""
import json
import requests
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from pydantic import ValidationError
from .lib.illumio import PolicyComputeEngine


class IllumioPlugin(PluginBase):
    def handle_error(self, resp: requests.Response) -> any:
        try:
            resp.raise_for_status()
            return resp.json()
        except ValueError as e:
            raise Exception(f"Illumio Plugin: failed to parse JSON ... {str(e)}") from e
            self.logger.error(f"Illumio Plugin: failed to parse JSON {str(e)}")
        except Exception as e:
            raise Exception(f"Illumio Plugin: Exception {str(e)}") from e
            self.logger.error(f"Illumio Plugin: Exception {str(e)}")

            
    def labeltoip(self, pce, label_scope):
        label_dimensions = label_scope.split(",")
        refs = []
        ips  = []
        for label in label_dimensions:
            key, value = label.split(":")
            labels = pce.labels.get(params={"key": key, "value": value})
            if len(labels) > 0:
                refs.append(labels[0].href)

        workloads = pce.workloads.get(params={'labels': json.dumps([refs])})

        for workload in workloads:
            for interface in workload.interfaces:
                try:
                    print("Illumio Plugin Successfully retrieved IP: " + str(interface.address))
                    ips.append(interface.address)

                except ValidationError as err:
                    print("Error occurred while pulling Labels. Hence skipping")

        return ips

    def pull(self):
        """Pull IPs of desired Labels from PCE"""
        """Get all content from location configured on the plugin"""
        config = self.configuration

        """Setting PCE API details"""
        pce = PolicyComputeEngine(config["api_url"], port=config["api_port"], org_id=config["org_id"])
        pce.set_credentials(config["api_username"], config["api_password"])
        
        indicators = []
        ips = self.labeltoip(pce, config["label_scope"])
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
        self.logger.info("Illumio Plugin: Executing validate method for Sample plugin")
        if "api_url" not in data or not isinstance(data["api_url"], str) or not data["api_url"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API URL is required."
            )
            return ValidationResult(success=False, message="Invalid API URL provided.")
        elif "api_username" not in data or not isinstance(data["api_username"], str) or not data["api_username"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API Username is required with type string."
            )
            return ValidationResult(success=False, message="Invalid API Username provided.")
        elif "api_password" not in data or not isinstance(data["api_password"], str) or not data["api_password"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API Password is required with type string."
            )
            return ValidationResult(success=False, message="Invalid API Password provided.")
        elif "org_id" not in data or not isinstance(data["org_id"], int) or not data["org_id"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Org ID is required with type int."
            )
            return ValidationResult(success=False, message="Invalid Org ID provided.")
        elif "api_port" not in data or not isinstance(data["api_port"], int) or not data["api_port"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Port should be an integer."
            )
            return ValidationResult(success=False, message="Invalid Port provided.")
        elif "label_scope" not in data or not isinstance(data["label_scope"], str) or not data["label_scope"] or len(data["label_scope"].split(":")) < 2:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Label Scope is required with at least one key pair and described format"
            )
            return ValidationResult(success=False, message="Invalid Label Scope provided.")
        else:
            try:
                pce = PolicyComputeEngine(data["api_url"], port=data["api_port"], org_id=data["org_id"])
                pce.set_credentials(data["api_username"], data["api_password"])
                pce.must_connect()
            except Exception as e:
                return ValidationResult(success=False, message="Unable to connect to PCE: " + str(e))
            return ValidationResult(success=True, message="Validation successful.")

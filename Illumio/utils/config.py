# -*- coding: utf-8 -*-

"""Provides configuration utilities for the Illumio plugin.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
from dataclasses import dataclass, fields


@dataclass
class IllumioPluginConfig:
    """Dataclass to use as plugin configuration object.

    Performs type validation on the parameters in post-init.

    Raises:
        ValueError: if the type of a given parameter is invalid or null.
    """
    pce_url: str
    pce_port: int
    org_id: int
    api_username: str
    api_secret: str
    label_scope: str

    def __post_init__(self):
        # handle type conversion for all fields, ignoring nulls
        for field in fields(self):
            val = getattr(self, field.name)
            if val is not None:
                if field.type is str:
                    setattr(self, field.name, str(val).strip())
                elif not isinstance(val, field.type):
                    try:
                        setattr(self, field.name, field.type(val))
                    except ValueError:
                        raise ValueError(f"{field.name}: invalid value {val}")
            else:
                raise ValueError(f"{field.name}: field cannot be null")


__all__ = [
    "IllumioPluginConfig",
]

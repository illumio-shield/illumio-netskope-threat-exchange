from dataclasses import dataclass, fields


@dataclass
class IllumioPluginConfig:
    pce_url: str
    pce_port: int
    org_id: int
    api_username: str
    api_secret: str
    label_scope: str

    def __post_init__(self):
        # handle type conversion for all fields, ignoring nulls
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None:
                if field.type is str:
                    setattr(self, field.name, str(value).strip())
                elif not isinstance(value, field.type):
                    try:
                        setattr(self, field.name, field.type(value))
                    except ValueError:
                        raise ValueError(f"{field.name}: invalid value {value}")
            else:
                raise ValueError(f"{field.name}: field cannot be null")


__all__ = [
    "IllumioPluginConfig",
]

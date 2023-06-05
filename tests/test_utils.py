from contextlib import suppress as does_not_raise

import pytest

from Illumio import utils


@pytest.mark.parametrize(
    "label_scope,expected_result,labels", [
        ('', does_not_raise(), {}),  # should be caught as a validation error
        ('loc:quarantine', does_not_raise(), {'loc': 'quarantine'}),
        ('  loc  :  quarantine  ', does_not_raise(), {'loc': 'quarantine'}),
        ('loc: quarantine,', does_not_raise(), {'loc': 'quarantine'}),
        (
            'loc:quarantine, app:quarantine, env:quarantine',
            does_not_raise(),
            {'loc': 'quarantine', 'app': 'quarantine', 'env': 'quarantine'}
        ),
        (
            'loc=quarantine, app=quarantine, env=quarantine',
            pytest.raises(ValueError),
            None
        ),
        ('quarantine', pytest.raises(ValueError), None),
    ]
)
def test_parse_label_scopes(label_scope, expected_result, labels):
    with expected_result:
        parsed_labels = utils.parse_label_scope(label_scope)
        assert parsed_labels == labels


@pytest.mark.parametrize(
    "conf,expected_result", [
        ({}, pytest.raises(TypeError)),  # missing required fields
        (
            {
                'pce_url': 'my.pce.com',
                'pce_port': 8443,
                'org_id': 1,
                'api_username': 'api_username',
                'api_secret': 'apisecretxyz',
                'label_scope': 'loc:quarantine'
            },
            does_not_raise()
        ),
        (
            {
                'pce_url': 'my.pce.com',
                'pce_port': '8443',
                'org_id': '1',
                'api_username': 'api_username',
                'api_secret': 'apisecretxyz',
                'label_scope': 'loc:quarantine'
            },
            does_not_raise()
        ),
        (
            {
                'pce_url': 'http://my.pce.com',
                'pce_port': 8080,
                'org_id': 1,
                'api_username': 'api_username',
                'api_secret': 'apisecretxyz',
                'label_scope': 'loc:quarantine'
            },
            does_not_raise()
        ),
        (
            {
                'pce_url': 'my.pce.com',
                'pce_port': 8443,
                'org_id': 'invalid_value',
                'api_username': 'api_username',
                'api_secret': 'apisecretxyz',
                'label_scope': 'loc:quarantine'
            },
            pytest.raises(ValueError)
        ),
        (
            {
                'pce_url': 'my.pce.com',
                'pce_port': 8443,
                'org_id': 1,
                'api_username': 'api_username',
                'api_secret': 'apisecretxyz',
                'label_scope': None
            },
            pytest.raises(ValueError)
        ),
    ]
)
def test_plugin_configuration(conf, expected_result):
    with expected_result:
        config_obj = utils.IllumioPluginConfig(**conf)
        assert config_obj

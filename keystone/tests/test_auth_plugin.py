# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid
import mock
import os

from six.moves import urllib
from keystone import auth
from keystone import exception
from keystone import tests
from keystone.tests import core
from keystone.tests.ksfixtures import database
from keystone.tests import default_fixtures

# for testing purposes only
METHOD_NAME = 'simple_challenge_response'
EXPECTED_RESPONSE = uuid.uuid4().hex
DEMO_USER_ID = uuid.uuid4().hex


class SimpleChallengeResponse(auth.AuthMethodHandler):

    method = METHOD_NAME

    def authenticate(self, context, auth_payload, user_context):
        if 'response' in auth_payload:
            if auth_payload['response'] != EXPECTED_RESPONSE:
                raise exception.Unauthorized('Wrong answer')
            user_context['user_id'] = DEMO_USER_ID
        else:
            return {"challenge": "What's the name of your high school?"}


class DuplicateAuthPlugin(SimpleChallengeResponse):
    """Duplicate simple challenge response auth plugin."""


class MismatchedAuthPlugin(SimpleChallengeResponse):
    method = uuid.uuid4().hex


class NoMethodAuthPlugin(auth.AuthMethodHandler):
    """An auth plugin that does not supply a method attribute."""
    def authenticate(self, context, auth_payload, auth_context):
        pass


class TestAuthPlugin(tests.SQLDriverOverrides, tests.TestCase):
    def setUp(self):
        super(TestAuthPlugin, self).setUp()
        self.load_backends()

        self.api = auth.controllers.Auth()

    def config_files(self):
        config_files = super(TestAuthPlugin, self).config_files()
        config_files.append(tests.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files

    def config_overrides(self):
        super(TestAuthPlugin, self).config_overrides()
        method_opts = dict(
            [
                ('external', 'keystone.auth.plugins.external.DefaultDomain'),
                ('password', 'keystone.auth.plugins.password.Password'),
                ('token', 'keystone.auth.plugins.token.Token'),
                (METHOD_NAME,
                 'keystone.tests.test_auth_plugin.SimpleChallengeResponse'),
            ])
        self.auth_plugin_config_override(
            methods=['external', 'password', 'token', METHOD_NAME],
            **method_opts)

    def test_unsupported_auth_method(self):
        method_name = uuid.uuid4().hex
        auth_data = {'methods': [method_name]}
        auth_data[method_name] = {'test': 'test'}
        auth_data = {'identity': auth_data}
        self.assertRaises(exception.AuthMethodNotSupported,
                          auth.controllers.AuthInfo.create,
                          None,
                          auth_data)

    def test_addition_auth_steps(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'test': 'test'}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        try:
            self.api.authenticate({'environment': {}}, auth_info, auth_context)
        except exception.AdditionalAuthRequired as e:
            self.assertIn('methods', e.authentication)
            self.assertIn(METHOD_NAME, e.authentication['methods'])
            self.assertIn(METHOD_NAME, e.authentication)
            self.assertIn('challenge', e.authentication[METHOD_NAME])

        # test correct response
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'response': EXPECTED_RESPONSE}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.api.authenticate({'environment': {}}, auth_info, auth_context)
        self.assertEqual(DEMO_USER_ID, auth_context['user_id'])

        # test incorrect response
        auth_data = {'methods': [METHOD_NAME]}
        auth_data[METHOD_NAME] = {
            'response': uuid.uuid4().hex}
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo.create(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.assertRaises(exception.Unauthorized,
                          self.api.authenticate,
                          {'environment': {}},
                          auth_info,
                          auth_context)


class TestAuthPluginDynamicOptions(TestAuthPlugin):
    def config_overrides(self):
        super(TestAuthPluginDynamicOptions, self).config_overrides()
        # Clear the override for the [auth] ``methods`` option so it is
        # possible to load the options from the config file.
        self.config_fixture.conf.clear_override('methods', group='auth')

    def config_files(self):
        config_files = super(TestAuthPluginDynamicOptions, self).config_files()
        config_files.append(tests.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files


class TestInvalidAuthMethodRegistration(tests.TestCase):
    def test_duplicate_auth_method_registration(self):
        self.config_fixture.config(
            group='auth',
            methods=[
                'keystone.tests.test_auth_plugin.SimpleChallengeResponse',
                'keystone.tests.test_auth_plugin.DuplicateAuthPlugin'])
        self.clear_auth_plugin_registry()
        self.assertRaises(ValueError, auth.controllers.load_auth_methods)

    def test_no_method_attribute_auth_method_by_class_name_registration(self):
        self.config_fixture.config(
            group='auth',
            methods=['keystone.tests.test_auth_plugin.NoMethodAuthPlugin'])
        self.clear_auth_plugin_registry()
        self.assertRaises(ValueError, auth.controllers.load_auth_methods)


class TestInferredDomain(tests.TestCase):
    def setUp(self):
        self.useFixture(database.Database())
        super(TestInferredDomain, self).setUp()
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.subj = auth.plugins.external.InferredDomain()

    # FOO is the username of a member of the default domain
    def test_when_user_is_found_in_default_domain(self):
        found_user = self.subj._authenticate("foo@domain.com@ssosite.com", None)
        self.assertEqual(found_user['name'], "foo@domain.com")

    def test_when_user_is_not_in_expected_format(self):
        self.assertRaises(exception.Unauthorized,
                          self.subj._authenticate,
                          "THIS_IS_THE_WRONG_FORMAT",
                          None)

    def test_when_remote_user_is_none(self):
        found_user = self.subj._authenticate(None, None)
        self.assertEqual(found_user, {})

    # SUNGARD_FOO is the username of a member of a domain that is NOT default
    def test_when_user_is_found_in_different_domain(self):
        found_user = self.subj._authenticate(
            "sungard@domain.com@ssosite.com", None)
        self.assertEqual(found_user['name'], "sungard@domain.com")

    def test_when_user_is_missing(self):
        found_user = self.subj._authenticate(
            "MISSING@domain.com@ssosite.com", None)
        self.assertEqual(found_user, {})

    def test_when_user_is_disabled(self):
        found_user = self.subj._authenticate("disabled-user@domain.com", None)
        # self.assertEqual(found_user['name'], "sungard@domain.com")
        # self.assertRaises(
        #     exception.Unauthorized,
        #     self.subj._authenticate,
        #     "disabled-user@domain.com",
        #     None
        # )



class TestAuthControllersSsoAuth(tests.TestCase):
    SSO_TEMPLATE_NAME = 'sso_callback_template.html'
    SSO_TEMPLATE_PATH = os.path.join(core.dirs.etc(), SSO_TEMPLATE_NAME)
    TRUSTED_DASHBOARD = 'http://horizon.com'
    ORIGIN = urllib.parse.quote_plus(TRUSTED_DASHBOARD)
    METHOD_NAME = 'keystone.auth.plugins.external.InferredDomain'

    def setUp(self):
        self.useFixture(database.Database())
        super(TestAuthControllersSsoAuth, self).setUp()

        self.load_backends()
        self.load_fixtures(default_fixtures)

        self.auth_controller = auth.controllers.Auth()
        self.config_fixture.config(
            group='federation',
            trusted_dashboard=[self.TRUSTED_DASHBOARD],
            sso_callback_template=self.SSO_TEMPLATE_PATH)
        self.config_overrides

    def config_overrides(self):
        super(TestAuthControllersSsoAuth, self).config_overrides()
        method_opts = dict(
            [
                ('external', 'keystone.auth.plugins.external.InferredDomain'),
                ('password', 'keystone.auth.plugins.password.Password'),
                ('token', 'keystone.auth.plugins.token.Token'),
            ])
        self.auth_plugin_config_override(
            methods=['external', 'password', 'token'],
            **method_opts)


    def test_render_callback_template(self):
        token_id = uuid.uuid4().hex
        auth_controller = self.auth_controller
        resp = auth_controller.render_html_response(self.TRUSTED_DASHBOARD,
                                                    token_id)
        self.assertIn(token_id, resp.body)
        self.assertIn(self.TRUSTED_DASHBOARD, resp.body)

    def test_federated_sso_missing_query(self):
        context = {'environment': {}, 'query_string': []}
        self.assertRaises(exception.ValidationError,
                          self.auth_controller.sso_auth,
                          context)

    def test_federated_sso_untrusted_dashboard(self):
        context = {
            'environment': {},
            'query_string': {'origin': "I AM NOT TRUSTED"},
        }
        self.assertRaises(exception.Unauthorized,
                          self.auth_controller.sso_auth,
                          context)

    def test_redirect_from_SSO_login(self):
        context = {
            'environment': {
                'REMOTE_USER': "FOO@ssosite.com"
            },
            'query_string': {'origin': self.ORIGIN}
        }
        resp = self.auth_controller.sso_auth(context)
        self.assertIn(self.TRUSTED_DASHBOARD, resp.body)


class TestMapped(tests.TestCase):
    def setUp(self):
        super(TestMapped, self).setUp()
        self.load_backends()

        self.api = auth.controllers.Auth()

    def config_files(self):
        config_files = super(TestMapped, self).config_files()
        config_files.append(tests.dirs.tests_conf('test_auth_plugin.conf'))
        return config_files

    def config_overrides(self):
        # don't override configs so we can use test_auth_plugin.conf only
        pass

    def _test_mapped_invocation_with_method_name(self, method_name):
        with mock.patch.object(auth.plugins.mapped.Mapped,
                               'authenticate',
                               return_value=None) as authenticate:
            context = {'environment': {}}
            auth_data = {
                'identity': {
                    'methods': [method_name],
                    method_name: {'protocol': method_name},
                }
            }
            auth_info = auth.controllers.AuthInfo.create(context, auth_data)
            auth_context = {'extras': {},
                            'method_names': [],
                            'user_id': uuid.uuid4().hex}
            self.api.authenticate(context, auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((context, auth_payload, auth_context),
             kwargs) = authenticate.call_args
            self.assertEqual(method_name, auth_payload['protocol'])

    def test_mapped_with_remote_user(self):
        with mock.patch.object(auth.plugins.mapped.Mapped,
                               'authenticate',
                               return_value=None) as authenticate:
            # external plugin should fail and pass to mapped plugin
            method_name = 'saml2'
            auth_data = {'methods': [method_name]}
            # put the method name in the payload so its easier to correlate
            # method name with payload
            auth_data[method_name] = {'protocol': method_name}
            auth_data = {'identity': auth_data}
            auth_info = auth.controllers.AuthInfo.create(None, auth_data)
            auth_context = {'extras': {},
                            'method_names': [],
                            'user_id': uuid.uuid4().hex}
            environment = {'environment': {'REMOTE_USER': 'foo@idp.com'}}
            self.api.authenticate(environment, auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((context, auth_payload, auth_context),
             kwargs) = authenticate.call_args
            self.assertEqual(auth_payload['protocol'], method_name)

    def test_supporting_multiple_methods(self):
        for method_name in ['saml2', 'openid', 'x509']:
            self._test_mapped_invocation_with_method_name(method_name)

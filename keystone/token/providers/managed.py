"""Token provider for managed workplaces.

If a workplace is flagged as a managed via the `sgas_managed` flag, a role
named "sgas_managed" will be added to the user's workplace-scoped token.

Domain-scoped tokens are unaffected.

"""

from __future__ import absolute_import

from keystone.token.providers import common, uuid


class Provider(uuid.Provider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)
        self.v3_token_data_helper = V3ManagedTokenDataHelper()


class V3ManagedTokenDataHelper(common.V3TokenDataHelper):
    def _get_filtered_project(self, project_id):
        project_ref = self.assignment_api.get_project(project_id)
        filtered_project = {
            'id': project_ref['id'],
            'name': project_ref['name'],
            'sgas_managed': project_ref.get('sgas_managed', False)}
        filtered_project['domain'] = self._get_filtered_domain(
            project_ref['domain_id'])
        return filtered_project

    def _populate_roles(self, token_data, user_id, domain_id, project_id,
                        trust, access_token):
        super(V3ManagedTokenDataHelper, self)._populate_roles(
            token_data, user_id, domain_id, project_id, trust, access_token)

        if access_token or not project_id:
            return

        project_token_data = token_data.get('project')
        if project_token_data and project_token_data.get('sgas_managed'):
            token_data['roles'].append(
                {'id': 'sgas_managed', 'name': 'sgas_managed'})


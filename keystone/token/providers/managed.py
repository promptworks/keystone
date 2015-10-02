"""Token provider for managed workplaces.

If a workplace is flagged as a managed via the `sgas_managed` flag, a role
named "sgas_managed" will be added to the user's workplace-scoped token.

Domain-scoped tokens are unaffected.

"""

from __future__ import absolute_import

from keystone.token.providers import uuid


class Provider(uuid.Provider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)


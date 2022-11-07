import os
import sys
import hvac
import json

# from arelion_toolbox.aws.cloudwatch import CloudwatchLoggerHandler
import urllib3
from typing import Tuple, Union, List

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__all__ = ["VaultHandler"]
# logger = CloudwatchLoggerHandler().get_logger()


class VaultHandler:
    """
    Class VaultHandler retrieves secrets from our vault cluster.
    Uses RoleID and SecretID which must be passed or set with enviroment variables (role_id and secret_id)
    or environment variables.
    """

    def __init__(
        self,
        url: str = None,
        role_id: str = None,
        secret_id: str = None,
    ):
        """
        Creation of the class instance.
        """
        self.role_id = role_id or os.environ.get("role_id")
        self.secret_id = secret_id or os.environ.get("secret_id")
        self.url = url or os.environ.get("VAULT_ADDR")

    def _approle_login(self, verify: bool) -> hvac.v1.Client:
        """Internal method to login with approle

        Args:
            verify (bool, optional): Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault, or a string pointing
        at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification.

        Returns:
            hvac.v1.Client
        """
        client = hvac.Client(url=self.url, verify=verify)

        response = client.auth.approle.login(
            role_id=self.role_id,
            secret_id=self.secret_id,
        )
        if response["auth"]["client_token"]:
            client.token = response["auth"]["client_token"]
            return client
        logger.error("Error while fetching secrets from Vault, unable to fetch token")

    def _check_hvac_client_login(self, verify: bool = False) -> hvac.v1.Client:
        """Internal method to login with approle

        Args:
            verify (bool, optional): Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault, or a string pointing
        at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification. Defaults to False.

        Returns:
            hvac.v1.Client
        """
        try:
            client = hvac.Client(url=self.url, verify=verify)

            client.token = client.auth.approle.login(self.role_id, self.secret_id)["auth"]["client_token"]
            return client
        except Exception as e:
            print(f"Vault Handler error, cannot authenticate client: {e}")
            return

    def _check_env_credentials(self) -> bool:
        """Internal function that checks env-variables for login credentials (role_id and secret_id)

        Returns:
            bool: True if role_id and secret_id exists in env variables
        """
        return os.environ.get("role_id") is not None and os.environ.get("secret_id") is not None

    def _set_environments(self, env: dict) -> None:
        """Internal function that sets env-variables from provided dict. E.g. config retrieved from Vault

        Args:
            env (dict): dictionary containing credentials to set in environment variables

        Returns:
            None
        """
        for key in env.keys():

            if key.startswith("VAULT_PATH_"):
                """
                This section allows to auto-retrieve chunk secret in config by prefix VAULT_PATH_{something}
                """
                (state, secrets) = self.get_secret(env[key])
                if state:
                    for secret in secrets.keys():
                        if secret not in os.environ:
                            os.environ[secret] = secrets[secret]
                        else:
                            raise Exception(
                                f"VAULT_PATH DUPLICATED environment in config: {key} => {env[key]} => {secret} "
                            )
                else:
                    raise Exception(f"VAULT_PATH cannot retrieve secret in config: {key} => {env[key]} ")

            try:
                if key not in os.environ:
                    os.environ[key] = env[key]
                else:
                    print(
                        f"DUPLICATED environment in config: {key}. We have already: {os.environ[key]}, Want to set inplace: {env[key]}"
                    )
                    raise Exception(f"DUPLICATED environment in config: {key}")
            # parse dictionary as string to store in environment variables
            except TypeError as te:
                os.environ[key] = json.dumps(env[key])

    def read_path(self, path: str | list, environ: bool = False, verify: bool = True) -> dict:
        """Retrieve secrets from provided path in vault cluster. Access rights must be configured in policies!

        Args:
            path (str | list): The path of the secret/config that should be read
            environ (bool, optional): If true, secrets/config is also placed in environment variables. Defaults to False.
            verify (bool, optional): Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault, or a string pointing
        at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification. Defaults to True.

        Returns:
            dict: _description_
        """
        if not self._check_env_credentials():
            logger.error(
                "Error while fetching secrets from Vault, role_id and/or secret_id not present as environments variables."
            )
            raise

        client = self._approle_login(verify=verify)
        if not client.token:
            logger.error(
                "Error while fetching secrets from Vault, cannot instantiate hvac.Client class while using: approle.login"
            )
            raise

        paths = []
        paths = paths + (path if isinstance(path, list) else [path])

        results = {}
        for path in paths:
            response = client.secrets.kv.v2.read_secret(path=path)
            data = response["data"]["data"]

            # if keys of dict intersect then return False; no keys can be the same while updating
            if data.keys() & results.keys():
                logger.error(
                    f"Error while fetching secrets from Vault, duplicate keys fetched: {list(data.keys() & results.keys())}"
                )
                raise

            results.update(data)

        if environ:
            for key, value in results.items():
                os.environ[key] = value

        return results

    # @staticmethod
    def get_secret(self, path: str) -> tuple:
        """DEPRECATED -- Use read_path
        Retrieve secrets from provided path in vault cluster. Access rights must be configured in policies!

        Args:
            path (str): path vault in consul

        Returns:
            (bool): flag determines whether credentials were properly obtained (True)
            (dict): dictionary contains key: value paris of login and password if above mentioned flag is set to True;
                otherwise it contains dictionary with with errors

        Raises:
            ValueError: when role_id and/or secret_id not defined
            ValueError: when cannot get token for hvac.Client
        """
        logger.warning("get_secret is deprecated in favor of read_path. Please update your code")
        # check whether credentials exists
        if not (self._check_env_credentials()):
            raise ValueError("role_id and/or secret_id not present as environment variable")

        # check whether can get token for hvac.Client
        client = self._check_hvac_client_login()
        if not client.token:
            raise ValueError("cannot instantiate hvac.Client class while using: approle.login")

        secret_list = []
        if isinstance(path, list):
            secret_list = secret_list + path
        else:
            secret_list = secret_list + [path]

        result_dict = {}
        for single_path in secret_list:
            read_secret_result = client.secrets.kv.v2.read_secret(path=single_path)
            dict_with_secrets = read_secret_result["data"]["data"]

            # if keys of dict intersect then return False; no keys can be the same while updating
            if dict_with_secrets.keys() & result_dict.keys():
                duplicated_keys = dict_with_secrets.keys() & result_dict.keys()
                result_dict = {
                    "errors": (f"""duplicated key while dict update duplicated keys: {list(duplicated_keys)}""")
                }
                return False, result_dict

            result_dict.update(dict_with_secrets)
        return True, result_dict

    def get_config_path(self) -> None:
        """DEPRECATED -- Use read_path
        Function to retrieve specific config path. Config is read and placed in environment variables.
        Function works under the assumption that either  one of these exists:
            - appname (file_name.upper())
            - defined in environment path (DECONFPATH)

        Returns:
            None
        """
        logger.warning("get_config_path is deprecated in favor of read_path. Please update your code")
        os.environ["APPNAME"] = sys.argv[0].split("/")[-1].replace(".py", "").upper()
        if "DECONFPATH" in os.environ:
            (state, config) = self.get_secret(os.environ["DECONFPATH"])
            if state:
                self._set_environments(config)
            else:
                raise Exception(f"Path {os.environ['DECONFPATH']} cannot be retrieved from Vault. Check settings!")
        else:
            if "env" in os.environ:
                os.environ["DECONFPATH"] = f"dataeng/config/{os.environ['env'].upper()}/{os.environ['APPNAME']}"
                (state, config) = self.get_secret(os.environ["DECONFPATH"])
                if state:
                    self._set_environments(config)
                else:
                    raise Exception(f"Path {os.environ['DECONFPATH']} cannot be retrieved from Vault. Check settings!")
            else:
                raise Exception(f"Not able to determine CONFIG PATHS in DE environment (VAULT)")

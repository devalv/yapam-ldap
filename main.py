# -*- coding: utf-8 -*-

"""Yapam-ldap."""

__author__ = "Aleksei Devyatkin <aleksei@devyatkin.dev>"
import argparse
import asyncio
import sys
from json import dump as json_dump, load as json_load
from ssl import CERT_NONE
from typing import List

import httpx

from ldap3 import ALL, Connection, Server, Tls

from yapam.armory import Armory
from yapam.config import AmmoConfig


def load_created_users(users_file: str) -> List[dict]:
    """Open file with users list from a file."""
    with open(users_file, "r") as infile:
        users = json_load(infile)
    return users


class LdapWorker:
    """Ldap connection worker.

    Please use as context manager.

    Attributes:
        url: ldap url
        username: ldap username (probably with admin rights)
        password: ldap password
        users_file: file where created users should be saved or loaded from.
    """

    def __init__(self, url: str, username: str, password: str, users_file: str):
        """Please see help(LdapWorker) for more info."""
        self.tls_configuration = Tls(validate=CERT_NONE)
        self.url = url
        self.username = username
        self.password = password
        self.users_file = users_file

    def __open_connection(self):
        ldap_server = Server(
            host=self.url, get_info=ALL, use_ssl=True, tls=self.tls_configuration
        )
        connection = Connection(ldap_server, user=self.username, password=self.password)
        connected = connection.bind()
        if not connected:
            raise AssertionError("LDAP connection error: {}".format(connection.result))
        self.connection = connection
        return self.connection

    def __close_connection(self):
        return self.connection.unbind()

    def __enter__(self):
        """Open connection and return worker instance."""
        self.__open_connection()
        return self

    def __exit__(self, *args, **kwargs):
        """Close connection when job is done."""
        closed = self.__close_connection()
        if not closed:
            raise AssertionError(
                "Can`t close LDAP connection: {}".format(self.connection.result)
            )

    def __save_created_users(self, users: List[dict]):
        """Save created users to a file for feature operations."""
        with open(self.users_file, "w") as outfile:
            json_dump(users, outfile)

    def __create_user(self, username: str, password: str, ldap_domain: str) -> dict:
        """Create a new user in MS AD."""
        # make ldap filters
        dc_str = ",".join([f"dc={dc}" for dc in ldap_domain.split(".")])
        cn_str = f"cn={username},cn=Users,{dc_str}"
        principal_name = f"{username}@{ldap_domain}"
        # create user
        created = self.connection.add(
            cn_str,
            attributes={
                "objectClass": ["organizationalPerson", "person", "top", "user"],
                "sAMAccountName": username,
                "userPrincipalName": principal_name,
                "displayName": username,
                "givenName": username,
                "cn": username,
                "sn": username,
            },
        )
        if not created:
            raise AssertionError(
                "Can`t create a user {}: {}".format(username, self.connection.result)
            )
        # set password
        psw_set = self.connection.extend.microsoft.modify_password(cn_str, password)
        if not psw_set:
            raise AssertionError(
                "Can`t set password for a user {}: {}".format(
                    username, self.connection.result
                )
            )
        # enable user (after password set)
        enabled = self.connection.modify(
            cn_str, {"userAccountControl": [("MODIFY_REPLACE", 512)]}
        )
        if not enabled:
            raise AssertionError(
                "Can`t enable a user {}: {}".format(username, self.connection.result)
            )
        return {
            "username": username,
            "password": password,
            "principal_name": principal_name,
            "cn": cn_str,
        }

    def __delete_user(self, cn: str):
        """Delete existing user in MS AD."""
        return self.connection.delete(cn)

    def create_users(self, password: str, ldap_domain: str, count: int) -> List[dict]:
        """Create several users in MS AD."""
        created_users = list()
        for i in range(count):
            created_user = self.__create_user(
                username=f"tank.user{i + 1}", password=password, ldap_domain=ldap_domain
            )
            created_users.append(created_user)
        self.__save_created_users(users=created_users)
        return created_users

    def delete_users(self, users_list: List[dict] = None) -> List[dict]:
        """Delete several users in MS AD."""
        deleted_users = list()
        if not users_list:
            users_list = load_created_users(self.users_file)
        for user in users_list:
            self.__delete_user(cn=user["cn"])
            deleted_users.append(user)
        return deleted_users


class YapamWorker:
    """Yapam worker.

    Attributes:
        method: ammo method for shooting
        port: ammo port for shooting
        host: ammo host for shooting
        api_url: ammo url for shooting
        yapam_config: file where yapam configuration file will be saved
        case: case for tank graph
        ammo_file: file where ammo should be saved (default is ammo)
    """

    def __init__(
        self,
        method: str,
        host: str,
        api_url: str,
        yapam_config: str,
        port: int = 443,
        case: str = None,
        ammo_file: str = "ammo",
    ):
        """Please see help(YapamWorker) for more info."""
        self.host = host
        self.api_url = api_url
        self.yapam_config = yapam_config
        self.method = method
        self.port = port
        self.case = case
        self.ammo_file = ammo_file

    def __create_auth_requests(self, users_list: List[dict]) -> List[dict]:
        """Create requests for yapam config.json."""
        requests = list()
        for user in users_list:
            request = {
                "host": self.host,
                "url": self.api_url,
                "port": self.port,
                "method": self.method,
                "body": {
                    "username": user["username"],
                    "password": user["password"],
                    "ldap": True,
                },
            }
            if self.case:
                request["case"] = self.case
            requests.append(request)
        return requests

    def __create_jwt_requests(self, users_list: List[dict]) -> [dict]:
        """Create requests with authentication."""
        requests = list()
        for user in users_list:
            request = {
                "host": self.host,
                "url": self.api_url,
                "port": self.port,
                "method": self.method,
                "extra_headers": {"Authentication": user["access_token"]},
            }
            if self.case:
                request["case"] = self.case
            requests.append(request)
        return requests

    def __create_config(self, requests: List[dict]) -> bool:
        """Make a yapam configuration file."""
        config_dict = {
            "AMMO_FILE": self.ammo_file,
            "LOG_DATE_FMT": "%H:%M:%S",
            "LOG_FMT": "%(asctime)s.%(msecs)d|%(levelname).1s|%(message)s",
            "LOG_LVL": "INFO",
            "REQUESTS": requests,
        }
        # write config to a file
        with open(self.yapam_config, "w") as outfile:
            json_dump(config_dict, outfile)
        return True

    def __create_tank_ammo(self) -> str:
        """Create yandex-tank ammo."""
        user_config = AmmoConfig(self.yapam_config)
        armory = Armory(user_config.requests, user_config.ammo_file, user_config.log)
        armory.generate_ammo()
        return user_config.ammo_file

    def make_auth_ammo(self, users_list: List[dict]) -> str:
        """Create yandex-tank ammo for authentication testing."""
        requests = self.__create_auth_requests(users_list=users_list)
        config_created = self.__create_config(requests=requests)
        if not config_created:
            raise AssertionError("Can`t create yapam config.")
        return self.__create_tank_ammo()

    def make_jwt_ammo(self, users_list: List[dict]) -> str:
        """Create yandex-tank ammo for existing users."""
        requests = self.__create_jwt_requests(users_list=users_list)
        config_created = self.__create_config(requests=requests)
        if not config_created:
            raise AssertionError("Can`t create yapam config.")
        return self.__create_tank_ammo()


class VeilWorker:
    """Veil worker.

    Attributes:
        url: full url for a request (https://your.com/api/endpoint).
        users_file: file where created users should be loaded from.
        method: request method. Default is POST.
        port: port for a request. Default is 443.
        ldap: additional param for MS AD authentication. Default is True.
    """

    __USER_AGENT_VAL = "Yapam-ldap"

    def __init__(
        self,
        url: str,
        users_file: str,
        method: str = "POST",
        port: int = 443,
        ldap: bool = True,
    ):
        """Please see help(VeilWorker) for more info."""
        self.url = url
        self.method = method
        self.port = port
        self.users_file = users_file
        self.ldap = ldap

    @property
    def headers(self):
        """Headers for client."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "User-Agent": self.__USER_AGENT_VAL,
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0",
            "Accept-Language": "en",
        }

    def create_users_list(self) -> List[dict]:
        """Create authentication body."""
        created_users = load_created_users(self.users_file)
        auth_user_list = list()
        for user in created_users:
            auth_user = {
                "ldap": self.ldap,
                "username": user["username"],
                "password": user["password"],
            }
            auth_user_list.append(auth_user)
        return auth_user_list

    async def get_jwt_tokens(self) -> List[dict]:
        """Send authentication request to veil and collect response tokens."""
        authenticated_users_list = list()
        async with httpx.AsyncClient(headers=self.headers, verify=False) as client:
            for user in self.create_users_list():
                response = await client.request(
                    method=self.method, url=self.url, json=user, headers=self.headers
                )
                if response.status_code != httpx.codes.OK:
                    raise AssertionError("Failed to fetch response from VeiL.")
                response_data = response.json()
                if "errors" in response_data:
                    raise AssertionError(
                        f'Error in VeiL response:{response_data["errors"]}'
                    )
                if "data" not in response_data:
                    raise AssertionError("No data in VeiL response.")
                user_token = {
                    "username": response_data["data"]["username"],
                    "access_token": f'jwt {response_data["data"]["access_token"]}',
                }
                authenticated_users_list.append(user_token)
        return authenticated_users_list


def parse_args():
    """Script arguments parser."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        default="create",
        type=str,
        choices=["create", "delete", "auth"],
        help="Working mode",
    )
    return parser.parse_args()


async def main(
    ldap_conf: dict, tank_conf: dict, users_conf: dict, veil_conf: dict = None
):
    """Will work when script running directly."""
    args = parse_args()
    if args.mode == "create":
        print("Создаем пользователей")  # noqa: T001
        with LdapWorker(**ldap_conf) as ldap_w:
            yw = YapamWorker(**tank_conf)
            yw.make_auth_ammo(users_list=ldap_w.create_users(**users_conf))
    elif args.mode == "delete":
        print("Удаляем пользователей")  # noqa: T001
        with LdapWorker(**ldap_conf) as ldap_w:
            ldap_w.delete_users()
    elif args.mode == "auth":
        print("Генерируем патроны с предварительной авторизацией.")  # noqa: T001
        if not veil_conf:
            raise AssertionError("Veil conf is empty.")
        vw = VeilWorker(**veil_conf)
        authenticated_users = await vw.get_jwt_tokens()
        yw = YapamWorker(**tank_conf)
        yw.make_jwt_ammo(users_list=authenticated_users)
    else:
        sys.exit(1)

    print("Успешное завершение")  # noqa: T001
    sys.exit(0)


if __name__ == "__main__":

    ldap_configuration = {
        "url": "ldaps://192.168.14.167",
        "username": "secret",
        "password": "secret",
        "users_file": "created_users.json",
    }
    tank_configuration = {
        "host": "192.168.7.178",
        "api_url": "/api/auth",
        "yapam_config": "config.json",
        "method": "POST",
        "port": 443,
        "case": "LDAP_TANK_AUTH",
    }
    create_users_configuration = {
        "password": "secret!",
        "ldap_domain": "secret.domain",
        "count": 5,
    }
    veil_configuration = {
        "url": "https://192.168.7.178/api/auth",
        "users_file": "created_users.json",
        "method": "POST",
        "port": 443,
        "ldap": True,
    }

    asyncio.run(
        main(
            ldap_conf=ldap_configuration,
            tank_conf=tank_configuration,
            users_conf=create_users_configuration,
            veil_conf=veil_configuration,
        )
    )

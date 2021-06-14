[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# yapam-ldap
A useful (possibly) utility for generating Yandex-tank ammo.

## FAQ

### How to start
1. Create **venv** for your project.
2. Activate **venv** and install project requirements.
```bash
pip install -r requirements.txt
```
3. Go to the end of **main.py** and edit configuration dicts.
```python
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
```

4. Run (see examples below)

#### Create
Create temporary users on MS AD via LDAP.

```bash
venv/bin/python main.py --mode=create
```
In a result you`ll get 3 files:
* `config.json` - a temporary file just for extra debugging.
* `ammo` - ammo for a yandex tank shooting.
* `created_users.json` - users created on a ldap server.

#### Delete
Delete previously created users from MS AD via LDAP.

```bash
venv/bin/python main.py --mode=delete
```

Note, that your MS AD server should have ssl configuration.

#### Auth
Create ammo with authentication tokens from your api.

```bash
venv/bin/python main.py --mode=auth
```

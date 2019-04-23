polychaeta
==========

A GitHub bot for basic issue management tasks.

Usage
-----
- Install Python 3 on your system
- `pip3 install flask PyGithub apscheduler sqlalchemy dateparser`
- Copy `config.yaml.example` to `config.yaml`
- Set up your webhooks on GitHub, generate a webhook secret and put it in the
  `gh_webhook_secret` field
- Generate an auth token for the account you want the bot to use and put it in
  the `gh_auth_token field`
- Set environment variable `FLASK_APP=polychaeta.py`
- Execute `flask run`
- Configure your web server of choice to proxy your payload URL to
  `http://localhost:5000/payload` and reload it

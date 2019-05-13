frrbot
======

A GitHub bot for managing the FRRouting/frr repo.

Usage
-----
- Install Python 3 on your system
- `pip3 install flask PyGithub apscheduler sqlalchemy dateparser`
- Copy `config.yaml.example` to `config.yaml`
- Set up your webhooks on GitHub, generate a webhook secret and put it in the
  `gh_webhook_secret` field
- Generate an auth token for the account you want the bot to use and put it in
  the `gh_auth_token field`

*Option 1: `flask run`*

- Set environment variable `FLASK_APP=frrbot.py`
- Execute `flask run`
- Configure your web server of choice to proxy your payload URL to
  `http://localhost:5000/` and reload it

*Option 2: WSGI*

- Use `./run.sh` to create and mount a WSGI endpoint on /frrbot and
  configure your web server to WSGI proxy your pyaload URL to it.

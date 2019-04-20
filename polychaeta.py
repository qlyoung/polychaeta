#!/usr/bin/env python3
#
# Deps:
# pip3 install flask PyGithub apscheduler sqlalchemy
#
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from flask import Response
from flask import request
from github import Github
from hmac import HMAC
import datetime
import hmac
import json
import os
import yaml

# Global data ------------------------------------------------------------------
autoclosemsg = "This issue will be automatically closed in one week unless there is further activity."
noautoclosemsg = "This issue will no longer be automatically closed."
triggerlabel = "autoclose"

# Scheduler functions ----------------------------------------------------------


def close_issue(rn, num):
    app.logger.warning("Closing issue #{}".format(num))
    repo = g.get_repo(rn)
    issue = repo.get_issue(num)
    issue.edit(state="closed")
    issue.remove_from_labels(triggerlabel)


# Module init ------------------------------------------------------------------

print("[+] Loading config")

with open("config.yaml", "r") as conffile:
    conf = yaml.safe_load(conffile)
    whsec = conf["gh_webhook_secret"]
    auth = conf["gh_auth_token"]

print("[+] Github auth token: {}".format(auth))
print("[+] Github webhook secret: {}".format(whsec))

# Initialize GitHub API
g = Github(auth)
print("[+] Initialized GitHub API object")

# Initialize scheduler
jobstores = {"default": SQLAlchemyJobStore(url="sqlite:///jobs.sqlite")}
scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()
print("[+] Initialized scheduler")
print("[+] Current jobs:")
scheduler.print_jobs()

# Initialize Flask app
app = Flask(__name__)
print("[+] Initialized Flask app")

# Webhook handlers -------------------------------------------------------------


def issue_labeled(j):
    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]
    action = j["action"]

    issueid = "{}@@@{}".format(reponame, issuenum)
    repo = g.get_repo(reponame)
    issue = repo.get_issue(issuenum)

    if j["label"]["name"] == triggerlabel:
        closedate = datetime.datetime.now() + datetime.timedelta(weeks=1)
        scheduler.add_job(
            close_issue,
            run_date=closedate,
            args=[reponame, issuenum],
            id=issueid,
            replace_existing=True,
        )
        app.logger.warning("[-] Issue {} scheduled for closing".format(issueid))
        issue.create_comment(autoclosemsg)

    return Response("OK", 200)


def handle_issues(j):
    issue_actions = {"labeled": issue_labeled}
    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]
    action = j["action"]
    app.logger.warning("Repo: {}".format(reponame))
    app.logger.warning("Action: {}".format(action))
    app.logger.warning("Issue: {}".format(issuenum))

    if action in issue_actions:
        return issue_actions[action](j)
    else:
        app.logger.warning("Unknown issue action: {}".format(action))

    return Response("OK", 200)


def issue_comment_created(j):
    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]
    action = j["action"]

    issueid = "{}@@@{}".format(reponame, issuenum)
    repo = g.get_repo(reponame)
    issue = repo.get_issue(issuenum)

    if j["comment"]["body"] != autoclosemsg and scheduler.get_job(issueid) is not None:
        app.logger.warning("[-] Descheduling issue {} for closing".format(issueid))
        scheduler.remove_job(issueid)
        app.logger.warning("[-] Issue {} descheduled for closing".format(issueid))
        issue.remove_from_labels(triggerlabel)
        issue.create_comment(noautoclosemsg)

    return Response("OK", 200)


def handle_issue_comment(j):
    issue_comment_actions = {"created": issue_comment_created}
    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]
    action = j["action"]
    app.logger.warning("Repo: {}".format(reponame))
    app.logger.warning("Action: {}".format(action))
    app.logger.warning("Issue: {}".format(issuenum))

    if action in issue_comment_actions:
        return issue_comment_actions[action](j)
    else:
        app.logger.warning("Unknown issue_comment action: {}".format(action))

    return Response("OK", 200)


def handle_webhook(request):
    hooks = {"issues": handle_issues, "issue_comment": handle_issue_comment}
    evtype = request.headers["X_GITHUB_EVENT"]

    app.logger.warning("Handling webhook: {}".format(evtype))

    if evtype in hooks:
        j = request.get_json(silent=True)
        if not j:
            app.logger.warning("Could not parse payload as JSON")
            return Response("Bad JSON", 500)
        return hooks[evtype](j)
    else:
        app.logger.warning("Unknown event type: {}".format(evtype))

    return Response("OK", 200)


# Flask hooks ------------------------------------------------------------------


def gh_sig_valid(req):
    mydigest = "sha1=" + HMAC(bytes(whsec, "utf8"), req.get_data(), "sha1").hexdigest()
    ghdigest = req.headers["X_HUB_SIGNATURE"]
    comp = hmac.compare_digest(ghdigest, mydigest)
    app.logger.warning("Request: mine = {}, theirs = {}".format(mydigest, ghdigest))
    return comp


@app.route("/payload", methods=["GET", "POST"])
def parse_payload():
    try:
        if not gh_sig_valid(request):
            return Response("Unauthorized", 401)
    except:
        return Response("Unauthorized", 401)

    app.logger.warning("Got {}".format(request.method))

    if request.method == "POST":
        return handle_webhook(request)
    else:
        return Response("OK", 200)

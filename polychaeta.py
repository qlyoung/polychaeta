#!/usr/bin/env python3
#
# Deps:
# pip3 install flask PyGithub apscheduler
#
from flask import Flask
from flask import request
from flask import Response
from github import Github
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
import json
import hmac
from hmac import HMAC
import os
import yaml

print("[+] Loading config")

with open("config.yaml", "r") as conffile:
    conf = yaml.safe_load(conffile)
    whsec = conf["gh_webhook_secret"]
    auth = conf["gh_auth_token"]

print("[+] Github auth token: {}".format(auth))
print("[+] Github webhook secret: {}".format(whsec))

autoclosemsg = "This issue will be automatically closed in one week unless there is further activity."
noautoclosemsg = "This issue will no longer be automatically closed."
triggerlabel = "autoclose"

# Initialize GitHub API
g = Github(auth)
print("[+] Initialized GitHub API object")

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Initialize Flask app
app = Flask(__name__)
print("[+] Initialized Flask app")


def close_issue(rn, num):
    app.logger.warning("Closing issue #{}".format(num))
    repo = g.get_repo(rn)
    issu = repo.get_issue(num)
    issu.edit(state="closed")
    issu.remove_from_labels(triggerlabel)


def gh_sig_valid(req):
    mydigest = "sha1=" + HMAC(bytes(whsec, "utf8"), req.get_data(), "sha1").hexdigest()
    ghdigest = req.headers["X_HUB_SIGNATURE"]
    comp = hmac.compare_digest(ghdigest, mydigest)
    app.logger.warning("Request: mine = {}, theirs = {}".format(mydigest, ghdigest))
    return comp


@app.route("/payload", methods=["GET", "POST"])
def parse_payload():
    if not gh_sig_valid(request):
        return Response("Unauthorized", 401)

    if request.method == "POST":
        app.logger.warning("Got POST:")
        j = request.get_json()
        if "issue" not in j:
            return Response("OK", 200)
        reponame = j["repository"]["full_name"]
        issuenum = j["issue"]["number"]
        action = j["action"]
        app.logger.warning("Repo: {}".format(reponame))
        app.logger.warning("Action: {}".format(action))
        app.logger.warning("Issue: {}".format(issuenum))

        if action == "deleted":
            return Response("OK", 200)

        issueid = "{}@@@{}".format(reponame, issuenum)
        repo = g.get_repo(reponame)
        issue = repo.get_issue(issuenum)

        if action == "labeled" and j["label"]["name"] == triggerlabel:
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
        if action == "created" and "comment" in j:
            if (
                j["comment"]["body"] != autoclosemsg
                and scheduler.get_job(issueid) is not None
            ):
                app.logger.warning(
                    "[-] Issue {} no longer scheduled for closing".format(issueid)
                )
                issue.remove_from_labels(triggerlabel)
                issue.create_comment(noautoclosemsg)
                scheduler.remove_job(issueid)

        return Response("OK", 200)
    else:
        return Response("Unauthorized", 401)

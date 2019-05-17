#!/usr/bin/env python3
#
# Deps:
# pip3 install flask PyGithub apscheduler sqlalchemy dateparser
#
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from flask import Response
from flask import request
from github import Github
from github import GithubException
from hmac import HMAC
from werkzeug.exceptions import BadRequest
import dateparser
import datetime
import hmac
import json
import os
import re
import yaml

# Global data ------------------------------------------------------------------
autoclosemsg = "This issue will be automatically closed in one week unless there is further activity."
noautoclosemsg = "This issue will no longer be automatically closed."
triggerlabel = "autoclose"

pr_greeting_msg = "Thanks for your contribution to FRR!\n\n"
pr_warn_signoff_msg = "* One of your commits is missing a `Signed-off-by` line; we can't accept your contribution until all of your commits have one\n"
pr_warn_blankln_msg = "* One of your commits does not have a blank line between the summary and body; this will break `git log --oneline`\n"
pr_warn_commit_msg = (
    "* One of your commits has an improperly formatted commit message\n"
)
pr_guidelines_ref_msg = "\nIf you are a new contributor to FRR, please see our [contributing guidelines](http://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#coding-practices-style).\n"

# Scheduler functions ----------------------------------------------------------


def close_issue(rn, num):
    app.logger.warning("[+] Closing issue #{}".format(num))
    repo = g.get_repo(rn)
    issue = repo.get_issue(num)
    issue.edit(state="closed")
    try:
        issue.remove_from_labels(triggerlabel)
    except GithubException as e:
        pass


def schedule_close_issue(issue, when):
    """
    Schedule an issue to be automatically closed on a certain date.

    :param github.Issue.Issue issue: issue to close
    :param datetime.datetime when: When to close the issue
    """
    reponame = issue.repository.full_name
    issuenum = issue.number
    issueid = "{}@@@{}".format(reponame, issuenum)
    app.logger.warning(
        "[-] Scheduling issue #{} for autoclose (id: {})".format(issuenum, issueid)
    )
    scheduler.add_job(
        close_issue,
        run_date=when,
        args=[reponame, issuenum],
        id=issueid,
        replace_existing=True,
    )


def cancel_close_issue(issue):
    """
    Dechedule an issue to be automatically closed on a certain date.

    :param github.Issue.Issue issue: issue to cancel
    """
    reponame = issue.repository.full_name
    issuenum = issue.id
    issueid = "{}@@@{}".format(reponame, issuenum)
    app.logger.warning("[-] Descheduling issue #{} for closing".format(issuenum))
    scheduler.remove_job(issueid)


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
my_user = g.get_user().login
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
    issue = g.get_repo(reponame).get_issue(issuenum)

    def label_autoclose():
        closedate = datetime.datetime.now() + datetime.timedelta(weeks=1)
        schedule_close_issue(issue, closedate)
        issue.create_comment(autoclosemsg)

    label_actions = {"autoclose": label_autoclose}

    try:
        labelname = j["label"]["name"]
        label_actions[labelname]()
    except KeyError:
        pass

    return Response("OK", 200)


def issue_comment_created(j):
    """
    Handle an issue comment being created.

    First we check if the comment contains a trigger phrase. If it does, and
    the user who made the comment has admin privileges on the repository, we
    then try to parse the trigger phrase and its arguments and take the
    specified action. If the action fails to parse nothing is done.

    If the comment doesn't contain a trigger phrase, and this issue is
    scheduled for autoclose, then we'll consider the comment to be activity on
    the issue and cancel the autoclose.

    Trigger phrases are of the form '@<botusername> <verb> <arguments>.

    Current verbs:

    autoclose <time period>
       Automatically close this issue in <time period>.
    """

    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]

    repo = g.get_repo(reponame)
    issue = repo.get_issue(issuenum)

    body = j["comment"]["body"]
    sender = j["sender"]["login"]
    perm = repo.get_collaborator_permission(sender)

    def verb_autoclose(arg):
        """
        Verb to automatically close an issue after a certain period of time.

        :param tp str: trigger phrase
        :param arg str: automatically close this issue in <arg>, where <arg> is
        a time period in the future or a date. For instance, time period could
        be "in 1 day" to close the issue in 1 day, or "May 25th" to specify the
        next occurring May 15th.
        """
        if perm != "write" or perm != "admin":
            app.logger.warning("[-] User '{}' ({}) isn't authorized to use this command".format(sender, perm))
            return

        closedate = dateparser.parse(arg)
        if closedate is not None and closedate > datetime.datetime.now():
            schedule_close_issue(issue, closedate)
            issue.add_to_labels("autoclose")
            issue.get_comment(j["comment"]["id"]).create_reaction("+1")
        elif closedate is None:
            app.logger.warning("[-] Couldn't parse '{}' as a datetime".format(arg))

    verbs = {"autoclose": verb_autoclose}

    had_verb = False

    for verb in verbs.keys():
        tp = "@{} {} ".format(my_user, verb)
        if tp.lower() in body.lower():
            partition = body.lower().partition(tp.lower())
            app.logger.warning("[+] Trigger detected: {} {}".format(partition[1], partition[2]))
            verbs[verb](partition[2])
            had_verb = True

    issueid = "{}@@@{}".format(reponame, issuenum)
    if not had_verb and scheduler.get_job(issueid) is not None:
        scheduler.remove_job(issueid)
        issue.remove_from_labels(triggerlabel)
        issue.create_comment(noautoclosemsg)

    return Response("OK", 200)


def pull_request_opened(j):
    """
    Handle a pull request being opened.

    This function checks each commit's message for proper summary line
    formatting, Signed-off-by, and modified directories. If it finds formatting
    issues or missing Signed-off-by, it leaves a review on the PR asking for
    the problem to be fixed.

    Also, modified directories are extracted from commits and used to apply the
    corresponding topic labels.
    """
    reponame = j["repository"]["full_name"]

    repo = g.get_repo(reponame)
    pr = repo.get_pull(j["number"])
    commits = pr.get_commits()

    labels = set()

    # apply labels based on commit messages
    label_map = {
        "babeld": "babel",
        "bfdd": "bfd",
        "bgpd": "bgp",
        "debian": "packaging",
        "doc": "documentation",
        "docker": "docker",
        "eigrpd": "eigrp",
        "fpm": "fpm",
        "isisd": "isis",
        "ldpd": "ldp",
        "lib": "libfrr",
        "nhrpd": "nhrp",
        "ospf6d": "ospfv3",
        "ospfd": "ospf",
        "pbrd": "pbr",
        "pimd": "pim",
        "pkgsrc": "packaging",
        "python": "clippy",
        "redhat": "packaging",
        "ripd": "rip",
        "ripngd": "ripng",
        "sharpd": "sharp",
        "snapcraft": "packaging",
        "solaris": "packaging",
        "staticd": "staticd",
        "tests": "tests",
        "tools": "tools",
        "vtysh": "vtysh",
        "vrrpd": "vrrp",
        "watchfrr": "watchfrr",
        "yang": "yang",
        "zebra": "zebra",
        # files
        "configure.ac": "build",
        "makefile.am": "build",
        "bootstrap.sh": "build",
    }

    warn_bad_msg = False
    warn_signoff = False
    warn_blankln = False

    for commit in commits:
        msg = commit.commit.message

        if msg.startswith("Revert") or msg.startswith("Merge"):
            continue

        if len(msg.split('\n')) < 2 or len(msg.split('\n')[1]) > 0:
            warn_blankln = True

        match = re.match(r"^([^:\n]+):", msg)
        if match:
            lbls = map(lambda x: x.strip(), match.groups()[0].split(","))
            lbls = map(lambda x: x.lower(), lbls)
            lbls = filter(lambda x: x in label_map, lbls)
            lbls = map(lambda x: label_map[x], lbls)
            lbls = set(lbls)
            labels = labels | lbls
        else:
            warn_bad_msg = True

        if not "Signed-off-by:" in msg:
            warn_signoff = True

    if warn_bad_msg or warn_signoff or warn_blankln:
        comment = pr_greeting_msg
        comment += pr_warn_commit_msg if warn_bad_msg else ""
        comment += pr_warn_signoff_msg if warn_signoff else ""
        comment += pr_warn_blankln_msg if warn_blankln else ""
        comment += pr_guidelines_ref_msg
        pr.create_review(body=comment, event="REQUEST_CHANGES")

    if labels:
        pr.add_to_labels(*labels)

    return Response("OK", 200)


# API handler map
# {
#   'event1': {
#     'action1': ev1_action1_handler,
#     'action2': ev1_action2_handler,
#     ...
#   }
#   'event2': {
#     'action1': ev2_action1_handler,
#     'action2': ev2_action2_handler,
#     ...
#   }
# }
event_handlers = {
    "issues": {"labeled": issue_labeled},
    "issue_comment": {"created": issue_comment_created},
    "pull_request": {"opened": pull_request_opened},
}


def handle_webhook(request):
    try:
        evtype = request.headers["X_GITHUB_EVENT"]
    except KeyError as e:
        app.logger.warning("[-] No X-GitHub-Event header...")
        return Response("No X-GitHub-Event header", 400)

    app.logger.warning("[+] Handling webhook '{}'".format(evtype))

    try:
        event = event_handlers[evtype]
    except KeyError as e:
        app.logger.warning("[+] Unknown event '{}'".format(evtype))
        return Response("OK", 200)

    try:
        j = request.get_json()
    except BadRequest as e:
        app.logger.warning("[-] Could not parse payload as JSON")
        return Response("Bad JSON", 400)

    try:
        action = j["action"]
    except KeyError as e:
        app.logger.warning("[+] No action for event '{}'".format(evtype))
        return Response("OK", 200)

    try:
        handler = event_handlers[evtype][action]
    except KeyError as e:
        app.logger.warning("[+] No handler for action '{}'".format(action))
        return Response("OK", 200)

    try:
        sender = j["sender"]["login"]
        reponame = j["repository"]["full_name"]
        repo = g.get_repo(reponame)
        if sender == my_user:
            app.logger.warning("[+] Ignoring event triggered by me")
            return Response("OK", 200)
    except KeyError as e:
        pass

    app.logger.warning("[+] Handling action '{}' on event '{}'".format(action, evtype))
    return handler(j)


# Flask hooks ------------------------------------------------------------------


def gh_sig_valid(req):
    mydigest = "sha1=" + HMAC(bytes(whsec, "utf8"), req.get_data(), "sha1").hexdigest()
    ghdigest = req.headers["X_HUB_SIGNATURE"]
    comp = hmac.compare_digest(ghdigest, mydigest)
    app.logger.warning("[+] Request: mine = {}, theirs = {}".format(mydigest, ghdigest))
    return comp


@app.route("/", methods=["GET", "POST"])
def parse_payload():
    try:
        if not gh_sig_valid(request):
            return Response("Unauthorized", 401)
    except:
        return Response("Unauthorized", 401)

    if request.method == "POST":
        return handle_webhook(request)
    else:
        return Response("OK", 200)

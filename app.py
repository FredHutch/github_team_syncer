#!/usr/bin/env python3

"""
Zappa/Flask/Restful app to sync a org's membership with a team.
If a user is added to/removed from the org, add/remove that
user to/from the team.
"""

from ipaddress import ip_address, ip_network
import os
import sys
import time

from flask import Flask, request
from flask_restful import Resource, Api
from hammock import Hammock as Github
import requests


APP = Flask(__name__)
API = Api(APP)
GITHUB = Github("https://api.github.com")


def verify_env_vars():
    "verify correct env vars are set"
    for var in ["GITHUB_TOKEN", "GITHUB_ORG", "GITHUB_TEAM"]:
        if not os.getenv(var):
            print("Environment variable {} not set! Exiting.".format(var))
            sys.exit(1)


def get_headers():
    "get headers"
    headers = {}
    headers["Authorization"] = "token {}".format(os.getenv("GITHUB_TOKEN"))
    headers["Accept"] = "application/vnd.github.hellcat-preview+json"
    return headers


def get_paginated_results(url, delay=0.3):
    """
    Handle paginated results transparently, returning them as one list.
    """
    results = requests.get(url, headers=get_headers())
    if not "Link" in results.headers:
        return results.json()
    all_results = results.json()
    while True:
        if not 'rel="next"' in results.headers["Link"]:
            return all_results
        links = results.headers["Link"].split(",")
        nextpage = [x for x in links if 'rel="next"' in x][0]
        nextpage = nextpage.split(";")[0].replace("<", "").replace(">", "").strip()
        time.sleep(delay)
        results = requests.get(nextpage, headers=get_headers())
        all_results.extend(results.json())

    return all_results


def is_valid_ip(ip):  # pylint: disable=invalid-name
    "does request originate from a valid IP"
    whitelist = requests.get(str(GITHUB.meta)).json()["hooks"]

    client_ip_address = ip_address(ip)

    for valid_ip in whitelist:
        if client_ip_address in ip_network(valid_ip):
            return True
    return False


def is_authenticated(req):
    "make sure request comes from a valid IP"
    forwarded_for = u"{}".format(req.headers.get("X-Forwarded-For"))
    ip = req.remote_addr  # pylint: disable=invalid-name
    if ip == "127.0.0.1":
        return True
    if not forwarded_for:
        return False
    addrs = forwarded_for.split(", ")
    if len(addrs) > 1:
        addrs = addrs[-2 : len(addrs)]  # removes spoofers
    for addr in addrs:
        if is_valid_ip(addr):
            return True
    return False


class TeamSyncer(Resource):
    "REST resource"

    def post(self):  # pylint: disable=no-self-use, too-many-return-statements
        "POST method"
        if not is_authenticated(request):
            return {"message": "you are not authorized"}
        obj = request.get_json()

        if not "action" in obj:
            if "zen" in obj:
                return {"message": "how zen of you"}
            return {"message": "this is not an event we care about"}

        if not obj["action"] in ["member_added", "member_removed"]:
            return {"message": "ignoring the {} action".format(obj["action"])}
        adding = obj["action"] == "member_added"
        login = obj["membership"]["user"]["login"]
        teams = get_paginated_results(str(GITHUB.orgs(os.getenv("GITHUB_ORG")).teams))
        team = None
        for ateam in teams:
            if ateam["name"] == os.getenv("GITHUB_TEAM"):
                team = ateam
                break
        else:
            return {"message": "there is no {} team.".format(os.getenv("GITHUB_TEAM"))}
        members = get_paginated_results(str(GITHUB.teams(team["id"]).members))
        membernames = [x["login"] for x in members]
        if adding:
            if login in membernames:
                return {
                    "message": "{} is already a member of {}".format(
                        login, os.getenv("GITHUB_TEAM")
                    )
                }
            requests.put(
                str(GITHUB.teams(team["id"]).memberships(login)), headers=get_headers()
            )
        else:
            if login in membernames:
                requests.delete(
                    str(GITHUB.teams(team["id"]).memberships(login)),
                    headers=get_headers(),
                )
            else:
                return {
                    "message": "{} is not a member of {}".format(
                        login, os.getenv("GITHUB_TEAM")
                    )
                }

        return {"message": "OK"}


API.add_resource(TeamSyncer, "/")

if __name__ == "__main__":
    verify_env_vars()
    APP.run(debug=False)  # Change debug to True for testing.

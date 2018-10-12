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


CFG = {}


def verify_env_vars():
    "verify correct env vars are set"
    for var in ["GITHUB_TOKEN", "GITHUB_ORG", "GITHUB_TEAM"]:
        tmp = os.getenv(var)
        if not tmp:
            print("Environment variable {} not set! Exiting.".format(var))
            sys.exit(1)
        else:
            CFG[var] = tmp


HEADERS = {}


def setup_headers():
    "set up headers"
    HEADERS["Authorization"] = "token {}".format(CFG["GITHUB_TOKEN"])
    HEADERS["Accept"] = "application/vnd.github.hellcat-preview+json"


def get_paginated_results(url, delay=0.3):
    """
    Handle paginated results transparently, returning them as one list.
    """
    results = requests.get(url, headers=HEADERS)
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
        results = requests.get(nextpage, headers=HEADERS)
        all_results.extend(results.json())

    return all_results


class TeamSyncer(Resource):
    "REST resource"

    def post(self):  # pylint: disable=no-self-use
        "POST method"
        forwarded_for = u'{}'.format(request.headers.get('HTTP_X_FORWARDED_FOR'))
        ip = request.remote_addr # pylint: disable=invalid-name
        print("ip is {}".format(ip))
        print("forwarded_for: {}".format(forwarded_for))
        obj = request.get_json()

        # check to make sure request originates from localhost or a github ip
        # ideally we should be using a secret token as well.
        if ip == "127.0.0.1":
            pass # ok, we are developing
        elif forwarded_for:
            whitelist = requests.get(str(GITHUB.meta)).json()['hooks']
            client_ip_address = ip_address(forwarded_for)

            for valid_ip in whitelist:
                if client_ip_address in ip_network(valid_ip):
                    break
            else:
                return {'message': 'u r not authorized'}
        else:
            return {'message': 'u r not authorized'}
        if not obj["action"] in ["member_added", "member_removed"]:
            return {"message": "ignoring the {} action".format(obj["action"])}
        adding = obj["action"] == "member_added"
        login = obj["membership"]["user"]["login"]

        teams = get_paginated_results(str(GITHUB.orgs(CFG["GITHUB_ORG"]).teams))
        team = None
        for ateam in teams:
            if ateam["name"] == CFG["GITHUB_TEAM"]:
                team = ateam
        if not team:
            return {"message": "there is no {} team.".format(CFG["GITHUB_TEAM"])}
        members = get_paginated_results(str(GITHUB.teams(team["id"]).members))
        membernames = [x["login"] for x in members]
        if adding:
            if login in membernames:
                return {
                    "message": "{} is already a member of {}".format(
                        login, CFG["GITHUB_TEAM"]
                    )
                }
            else:
                result = requests.put(
                    str(GITHUB.teams(team["id"]).memberships(login)), headers=HEADERS
                )
                print(result.status_code)
                print(result.json())
        else:
            if login in membernames:
                result = requests.delete(
                    str(GITHUB.teams(team["id"]).memberships(login)), headers=HEADERS
                )
                print(result.status_code)
            else:
                return {
                    "message": "{} is not a member of {}".format(
                        login, CFG["GITHUB_TEAM"]
                    )
                }

        return {"message": "OK"}


API.add_resource(TeamSyncer, "/")

if __name__ == "__main__":
    verify_env_vars()
    setup_headers()
    APP.run(debug=True)  # TODO Change debug to False in production.
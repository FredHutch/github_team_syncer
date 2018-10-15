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
        tmp = os.getenv(var)
        if not tmp:
            print("Environment variable {} not set! Exiting.".format(var))
            sys.exit(1)


def get_headers():
    "get headers"
    headers = {}
    headers["Authorization"] = "token {}".format(os.getenv("GITHUB_TOKEN"))
    headers["Accept"] = "application/vnd.github.hellcat-preview+json"
    return headers


def setup_headers():
    "set up headers"


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


class TeamSyncer(Resource):
    "REST resource"

    def post(self):  # pylint: disable=no-self-use
        "POST method"
        forwarded_for = u"{}".format(request.headers.get("X-Forwarded-For"))
        print("forwarded_for is {}".format(forwarded_for))
        ip = request.remote_addr  # pylint: disable=invalid-name
        obj = request.get_json()

        # check to make sure request originates from localhost or a github ip
        # ideally we should be using a secret token as well.
        # if ip == "127.0.0.1": # FIXME UNCOMMENT THIS BIT
        #     print("we are localhost")
            # pass # ok, we are developing TODO FIXME uncomment
        if forwarded_for:
            addrs = forwarded_for.split(", ")

            whitelist = requests.get(str(GITHUB.meta)).json()["hooks"]

            for addr in addrs:
                print("addr is {}".format(addr))
                client_ip_address = ip_address(addr)

                for valid_ip in whitelist:
                    if client_ip_address in ip_network(valid_ip):
                        print(
                            "client ip address {} is in ip_network {}".format(
                                client_ip_address, valid_ip
                            )
                        )
                        break
                else: # if there was no break
                    print(
                        "no valid ip in whitelist segment {} for {}".format(
                            whitelist, client_ip_address
                        )
                    )
                    # break
            else: # if there was no break
                print("no valid ip in any of the provided ips")
                return {"message": "u r not authorized"}
        else:
            print("forwarded_for is not set, exiting")
            return {"message": "u r not authorized"}
        if True:
            return {'message': 'premature exit FIXME'}
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
            else:
                requests.put(
                    str(GITHUB.teams(team["id"]).memberships(login)),
                    headers=get_headers(),
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
    setup_headers()
    APP.run(debug=True)  # FIXME  TODO Change debug to True for testing.

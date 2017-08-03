#!/usr/bin/env python

import os
import datetime
import shutil
import json

from pykeepass import PyKeePass
from urlparse import urlparse

shutil.copyfile("in.kdbx", "out.kdbx")

kp = PyKeePass("out.kdbx", password="test")

groupLabels = {
    "passwords.Password": "Passwords",
    "webforms.WebForm": "Logins",
    "wallet.membership.Membership": "Memberships",
    "securenotes.SecureNote": "Notes",
    "wallet.government.Passport": "Passports",
    "wallet.computer.UnixServer": "Servers",
    "wallet.computer.Router": "Routers",
    "wallet.financial.BankAccountUS": "Bank Accounts",
    "wallet.financial.CreditCard": "Credit Cards",
    "wallet.computer.License": "Licenses",
}
groups = {}

def getGroup(item):
    group = groups.get(item["typeName"])
    if group:
        return group

    label = groupLabels.get(item["typeName"])
    if not label:
        raise Exception("Unknown type name {}".format(item["typeName"]))

    group = kp.add_group(kp.root_group, label)
    groups[item["typeName"]] = group
    return group

def getField(item, designation):
    secure = item["secureContents"]
    if "fields" in secure:
        for field in secure["fields"]:
            d = field.get("designation")
            if d == designation:
                return field["value"]

    return None


with open("in.1pif/data.1pif", "r") as fp:
    data = fp.read().strip().split("***5642bee8-a5ff-11dc-8314-0800200c9a66***")

for line in data:
    if line.strip() == "":
        continue

    item = json.loads(line.strip())
    if item.get("trashed"):
        continue

    group = getGroup(item)

    entry = kp.add_entry(group, item["title"], "", "")
    secure = item["secureContents"]

    # Username
    if "username" in secure:
        entry.username = secure["username"]
    else:
        entry.username = getField(item, "username")

    # Password
    if "password" in secure:
        entry.password = secure["password"]
    else:
        entry.password = getField(item, "password")

    # Other web fields
    if "fields" in secure:
        for field in secure["fields"]:
            d = field.get("designation")
            if d != "username" and d != "password":
                entry.set_custom_property("Web field: {}".format(field["name"]), field["value"])

    # Password history
    if "passwordHistory" in secure:
        for p in secure["passwordHistory"]:
            d = datetime.datetime.fromtimestamp(p["time"])
            entry.set_custom_property("Password history ({})".format(d), p["value"])

    # Find URL in fields
    if not entry.url:
        if "htmlAction" in secure:
            entry.url = secure["htmlAction"]

    # Membership fields
    if "membership_no" in secure and not entry.username:
        entry.username = secure["membership_no"]

    # Passport fields
    if "number" in secure and not entry.username:
        entry.username = secure["number"]

    # Router fields
    if "network_name" in secure and not entry.username:
        entry.username = secure["network_name"]
    if "wireless_password" in secure and not entry.password:
        entry.password = secure["wireless_password"]

    # Bank account
    if "iban" in secure and not entry.username:
        entry.username = secure["iban"]
    if "swift" in secure and not entry.username:
        entry.username = secure["swift"]
    if "routingNo" in secure and not entry.username:
        entry.username = secure["routingNo"]
    if "accountNo" in secure and not entry.username:
        entry.username = secure["accountNo"]
    if "telephonePin" in secure and not entry.password:
        entry.password = secure["telephonePin"]

    # Credit card
    if "ccnum" in secure and not entry.username:
        entry.username = secure["ccnum"]
    if "pin" in secure and not entry.password:
        entry.password = secure["pin"]

    # Sections
    if "sections" in secure:
        for s in secure["sections"]:
            t = s["title"]
            if "fields" in s:
                for f in s["fields"]:
                    v = f.get("v")
                    if not v:
                        continue
                    k = f["k"]
                    ft = "{} - {}".format(t, f["t"])
                    if t == "":
                        ft = f["t"]
                    if k == "string" or k == "concealed" or k == "menu" or k == "cctype" or k == "monthYear":
                        entry.set_custom_property(ft, str(v))
                    elif k == "date":
                        d = datetime.datetime.fromtimestamp(v)
                        entry.set_custom_property(ft, str(d))
                    else:
                        raise Exception("Unknown k: {}".format(k))

    # Notes
    if "notesPlain" in secure:
        entry.notes = secure["notesPlain"]

    # URLs
    settings = {
        "Allow": [],
        "Deny": [],
        "Realm": "",
    }
    applySettings = False

    if "location" in item:
        entry.url = item["location"]
    if "URLs" in secure:
        for u in secure["URLs"]:
            if not entry.url:
                entry.url = u["url"]
            url = urlparse(u["url"])
            settings["Allow"].append(url.hostname)
            applySettings = True

    if applySettings:
        settings["Allow"] = list(set(settings["Allow"]))
        entry.set_custom_property("KeePassHttp Settings", json.dumps(settings))


    # Dates
    entry.ctime = datetime.datetime.fromtimestamp(item["createdAt"])
    entry.mtime = datetime.datetime.fromtimestamp(item["updatedAt"])

kp.save()

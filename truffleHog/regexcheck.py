import re
import json
import os


def regexes():
    with open(os.path.join(os.path.dirname(__file__), "regexes.json"), "r") as f:
        regexes = json.loads(f.read())

    for key in regexes:
        regexes[key] = re.compile(regexes[key])

    return regexes

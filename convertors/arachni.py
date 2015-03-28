#!/usr/bin/env python

import os
import json
import argparse
import sys
import textwrap
import re
from os import path
from collections import OrderedDict


DEFAULT_EFFORT = 50


def slugify(filename):
    filename = re.sub(r'\W+', '-', filename.lower())
    return filename.strip("-")


def convert_multi_string(text):
    text = text.strip()
    if len(text) > 70:
        return textwrap.wrap(text, width=70,
                             expand_tabs=False,
                             break_on_hyphens=False,
                             replace_whitespace=False,
                             break_long_words=False)
    return text


def convert_file(arachni_file, vuln_id):
    with open(arachni_file) as f:
        arachni_data = json.load(f)

    result = OrderedDict([
        ("id", vuln_id),
        ("title", arachni_data["name"]),
        ("severity", arachni_data["severity"]),
        ("description", convert_multi_string(arachni_data["description"])),
        ("fix",
         OrderedDict([
             ("effort", DEFAULT_EFFORT),
             ("guidance", convert_multi_string(arachni_data.get("remedy_guidance", ""))),
         ])
         ),
    ])
    if "tags" in arachni_data and len(arachni_data["tags"]):
        result["tags"] = arachni_data["tags"]
    if "references" in arachni_data and len(arachni_data["references"]):
        result["references"] = [{"url": url, "title": title}
                                for title, url in arachni_data["references"].items()]
    return result


def main():
    parser = argparse.ArgumentParser(description='Convert arachni format to vulndb format')
    parser.add_argument('src', type=unicode, help='path to arachni files')
    parser.add_argument('dst', type=unicode, help='output path for vulndb files')
    parser.add_argument('--id', type=int, default=1, help='initial id')
    args = parser.parse_args()

    src = args.src
    if not path.exists(src):
        print("src path doesn't exist %s" % src)
        sys.exit(1)

    dst = args.dst
    if not path.exists(dst):
        print("dst path doesn't exist %s" % dst)
        sys.exit(1)

    vuln_id = args.id

    files = [f for f in os.listdir(src) if path.isfile(path.join(src, f))]
    converted_files = []
    for arachniFile in files:
        converted = convert_file(path.join(src, arachniFile), vuln_id)
        converted_files.append(converted)
        vuln_id += 1

    for arachniFile in converted_files:
        filename = slugify(arachniFile["title"])
        filename = "%d-%s.json" % (arachniFile["id"], filename)
        filename = path.join(dst, filename)
        with open(filename, "w") as f:
            json.dump(arachniFile, f, indent=2)


if __name__ == "__main__":
    main()
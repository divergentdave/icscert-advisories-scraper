#!/usr/bin/env python
import collections
import enum
import re
import sqlite3
import time
import urllib.parse

import bs4
import cachecontrol
import cachecontrol.caches.file_cache
import requests
import yaml

CWE_CLASSIFICATION = yaml.safe_load(open("cwe_classification.yaml"))

AdvisorySummary = collections.namedtuple(
    "AdvisorySummary",
    ["docid", "url", "title"]
)

Advisory = collections.namedtuple(
    "Advisory",
    ["docid", "url", "title", "html", "cwe_list", "automatic_classification"]
)


class MemoryUnsafetyClassification(enum.Enum):
    YES = 1
    NO = 2
    MAYBE = 3

    def to_string(self):
        return [None, "yes", "no", "maybe"][self.value]

    @classmethod
    def from_yaml(cls, value):
        if value is True or value == "yes":
            return cls.YES
        elif value is False or value == "no":
            return cls.NO
        elif value == "maybe":
            return cls.MAYBE
        else:
            raise ValueError("{!r} was not recognized as a classification"
                             .format(value))


def paginated_list_gen(session):
    list_url = "https://www.us-cert.gov/ics/advisories"
    page_count = 1
    while True:
        time.sleep(1)
        resp = session.get(list_url)
        doc = bs4.BeautifulSoup(resp.text, "lxml")

        results = doc.select(".view-ics-advisories .view-content li")
        if not results:
            raise Exception("No results found on {}".format(list_url))
        for result in results:
            docid_elems = result.select(
                ".views-field-field-ics-docid-advisory .field-content"
            )
            docid = docid_elems[0].get_text().strip()
            link = result.select(".views-field-title .field-content a")[0]
            advisory_url = urllib.parse.urljoin(list_url, link.attrs["href"])
            title = link.get_text().strip()
            yield AdvisorySummary(docid, advisory_url, title)

        next_links = doc.select("li.pager__item--next a")
        if next_links:
            next_href = next_links[0].attrs["href"]
            list_url = urllib.parse.urljoin(list_url, next_href)
            page_count += 1
        else:
            break
    if page_count == 1:
        raise Exception("Didn't find link to next page of results")


def analyze_advisory(summary, html):
    doc = bs4.BeautifulSoup(html, "lxml")
    article = doc.select("article.ics-advisory")[0]
    text = article.get_text()
    cwe_list = sorted(
        set(re.findall("CWE-[0-9]+", text)),
        key=lambda s: (len(s), s)
    )
    if not cwe_list:
        automatic_classification = MemoryUnsafetyClassification.MAYBE
    else:
        any_cwe_yes = False
        any_cwe_maybe = False
        for cwe in cwe_list:
            if cwe in CWE_CLASSIFICATION:
                classification = MemoryUnsafetyClassification.from_yaml(
                    CWE_CLASSIFICATION[cwe]
                )
            else:
                print("Warning: {} has not yet been classified".format(cwe))
                classification = MemoryUnsafetyClassification.MAYBE
            if classification == MemoryUnsafetyClassification.YES:
                any_cwe_yes = True
            elif classification == MemoryUnsafetyClassification.MAYBE:
                any_cwe_maybe = True
        if any_cwe_yes:
            automatic_classification = MemoryUnsafetyClassification.YES
        elif any_cwe_maybe:
            automatic_classification = MemoryUnsafetyClassification.MAYBE
        else:
            automatic_classification = MemoryUnsafetyClassification.NO
    return Advisory(
        summary.docid,
        summary.url,
        summary.title,
        html,
        cwe_list,
        automatic_classification
    )


def full_details_gen(session):
    for summary in paginated_list_gen(session):
        time.sleep(1)
        resp = session.get(summary.url)
        yield analyze_advisory(summary, resp.text)


def main():
    cache_prefix = "https://"
    file_cache = cachecontrol.caches.file_cache.FileCache(".advisory_cache")
    cache_adapter = cachecontrol.CacheControlAdapter(cache=file_cache)
    session = requests.Session()
    session.mount(cache_prefix, cache_adapter)

    conn = sqlite3.connect("advisories.db")
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS advisories ("
        "docid TEXT, "
        "url TEXT, "
        "title TEXT, "
        "html TEXT, "
        "automatic_classification TEXT"
        ")"
    )
    cur.execute("DELETE FROM advisories")

    for result in full_details_gen(session):
        print(
            result.docid,
            result.url,
            result.title,
            result.cwe_list,
            result.automatic_classification
        )
        cur.execute(
            "INSERT INTO advisories ("
            "docid, "
            "url, "
            "title, "
            "html, "
            "automatic_classification"
            ") "
            "VALUES(?, ?, ?, ?, ?)",
            (
                result.docid,
                result.url,
                result.title,
                result.html,
                result.automatic_classification.to_string(),
            )
        )

    conn.commit()


if __name__ == "__main__":
    main()

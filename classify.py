#!/usr/bin/env python
import os
import re
import sqlite3

import bs4
import yaml

CLASSIFICATION_PATH = "manual_classification.yaml"


def yaml_to_db(classifications, conn):
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS manual_classifications ("
        "docid TEXT PRIMARY KEY, "
        "manual_classification TEXT"
        ")"
    )
    cur.execute("DELETE FROM manual_classifications")
    for docid, manual_classification in classifications.items():
        cur.execute(
            "INSERT INTO manual_classifications ("
            "docid, "
            "manual_classification"
            ") "
            "VALUES(?, ?)",
            (docid, manual_classification)
        )


def extract_text(node):
    if isinstance(node, bs4.element.Tag):
        for child in node.children:
            yield from extract_text(child)
        if node.name in ("br", "div", "h3", "h4", "li", "p"):
            yield "\n"
    elif isinstance(node, bs4.element.NavigableString):
        yield node
    else:
        raise Exception("TODO {}".format(node))


def save_classification(classifications, conn, docid, value):
    classifications[docid] = value
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO manual_classifications "
        "(docid, manual_classification) "
        "VALUES(?, ?)",
        (docid, value)
    )


def parse_vulnerability_text(article):
    start = article.find("h3", string=re.compile("VULNERABILITY\\s+OVERVIEW"))
    vulnerability_text = ""
    if start:
        vulnerability_text = start.get_text() + "\n"
        for sibling in start.next_siblings:
            if isinstance(sibling, bs4.element.Tag):
                if sibling.name == "h3":
                    sibling_text = sibling.get_text()
                    subheading_match = re.match(
                        "[0-9]+\\.[0-9]+\\.[0-9]+\\s",
                        sibling_text
                    )
                    heading_match = re.match(
                        "[0-9]+\\.[0-9]+\\s",
                        sibling_text
                    )
                    if "BACKGROUND" in sibling_text:
                        break
                    elif re.search("VULNERABILITY\\s+DETAILS",
                                   sibling_text):
                        pass
                    elif heading_match:
                        break
                    elif subheading_match:
                        pass
                    elif "Begin Update" in sibling_text:
                        pass
                    elif "End Update" in sibling_text:
                        pass
                vulnerability_text += "".join(extract_text(sibling))
            elif isinstance(sibling, bs4.element.NavigableString):
                vulnerability_text += sibling
        vulnerability_text = re.sub("\n+", "\n", vulnerability_text)
        vulnerability_text = re.sub("[ \u00a0]+", " ", vulnerability_text)
        return vulnerability_text
    else:
        return None


def manual_classification_loop(classifications, conn):
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) "
        "FROM advisories "
        "LEFT JOIN manual_classifications "
        "ON advisories.docid=manual_classifications.docid "
        "WHERE advisories.automatic_classification='maybe' "
        "AND manual_classifications.manual_classification IS NULL"
    )
    print("{} advisories need to be classified".format(cur.fetchone()[0]))
    cur.execute(
        "SELECT advisories.docid, title, url, html "
        "FROM advisories "
        "LEFT JOIN manual_classifications "
        "ON advisories.docid=manual_classifications.docid "
        "WHERE advisories.automatic_classification='maybe' "
        "AND manual_classifications.manual_classification IS NULL"
    )
    for docid, title, url, html in cur.fetchall():
        doc = bs4.BeautifulSoup(html, "lxml")
        article = doc.select("article.ics-advisory")[0]
        print(docid, title)
        print(url)
        print(
            parse_vulnerability_text(article) or "".join(extract_text(article))
        )
        command = None
        while not command:
            inp = input("[y]es/[n]o/[m]aybe/[s]kip/[q]uit: ")
            if inp and inp[0] in "ynmsq":
                command = inp[0]
        if command == "q":
            break
        elif command == "y":
            save_classification(classifications, conn, docid, "yes")
        elif command == "n":
            save_classification(classifications, conn, docid, "no")
        elif command == "m":
            save_classification(classifications, conn, docid, "maybe")
        print()


def main():
    if os.path.isfile(CLASSIFICATION_PATH):
        with open(CLASSIFICATION_PATH) as f:
            classifications = yaml.safe_load(f)
    else:
        classifications = {}

    conn = sqlite3.connect("advisories.db")
    yaml_to_db(classifications, conn)

    manual_classification_loop(classifications, conn)

    yaml_to_db(classifications, conn)
    conn.commit()
    with open(CLASSIFICATION_PATH, "w") as f:
        yaml.safe_dump(classifications, f)


if __name__ == "__main__":
    main()

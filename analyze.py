#!/usr/bin/env python3
import sqlite3


def main():
    conn = sqlite3.connect("advisories.db")
    cur = conn.cursor()
    cur.execute(
        "CREATE TEMPORARY VIEW "
        "synthesis (docid, classification) AS "
        "SELECT "
        "advisories.docid, "
        "CASE "
        "WHEN manual_classifications.manual_classification NOT NULL "
        "THEN manual_classifications.manual_classification "
        "ELSE advisories.automatic_classification "
        "END "
        "FROM advisories "
        "LEFT OUTER JOIN manual_classifications "
        "ON advisories.docid=manual_classifications.docid"
    )
    cur.execute(
        "SELECT classification, COUNT(*) "
        "FROM synthesis "
        "GROUP BY classification"
    )
    for row in cur.fetchall():
        print(row[1], row[0])


if __name__ == "__main__":
    main()

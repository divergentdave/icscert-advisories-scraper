# icscert-advisories-scraper
Collecting and analyzing ICS-CERT advisories

These scripts download ICS-CERT advisories, cache them, and aid in their analysis. My goal here is to count how many of the ICS-CERT advisories are about vulnerabilities caused by memory unsafety. (hat tip to [@lazyfishbarrel](https://twitter.com/lazyfishbarrel)) In the first pass of the analysis, if CWE numbers are present in an advisory, those are checked to determine if memory unsafety is at issue. If there are no CWE numbers, or the CWE numbers are inconclusive about the nature of the issue, I then manually review and classify the advisory. At the end of this process, each advisory is tagged as `yes`/`no`/`maybe`, to indicate whether the vulnerabilities described in the advisory are due to memory unsafety.

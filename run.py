#!/usr/bin/env python3
"""CTI OSINT pipeline — Напрям 3 (Cyber Threat Intelligence / IoC enrichment).

Usage:
  python run.py -i examples/iocs.txt
  python run.py 8.8.8.8 example.com http://x.test/ 44d88612fea8a8f36de82e1278abb02f
"""
from __future__ import annotations
import argparse
import sys
from cti.ioc import parse_file
from cti.pipeline import run_pipeline


def main() -> int:
    ap = argparse.ArgumentParser(description="Automated CTI IoC enrichment pipeline")
    ap.add_argument("iocs", nargs="*", help="IoCs (IP/domain/URL/hash/email)")
    ap.add_argument("-i", "--input", help="text file with one IoC per line")
    ap.add_argument("-o", "--output", default="output", help="output base directory")
    args = ap.parse_args()

    indicators = list(args.iocs)
    if args.input:
        indicators += parse_file(args.input)
    if not indicators:
        ap.error("provide IoCs as arguments or via --input file")

    report, paths = run_pipeline(indicators, base=args.output)

    print("\n" + "=" * 60)
    print(f"  Загальний рівень загрози : {report.overall.upper()}")
    print(f"  Проаналізовано IoC       : {len(report.results)}")
    print(f"  HTML-звіт                : {paths['report_html']}")
    print(f"  Інтерактивний граф       : {paths['graph_html']}")
    print(f"  STIX 2.1 bundle          : {paths['stix']}")
    print(f"  Архів доказів            : {paths['archive']}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())

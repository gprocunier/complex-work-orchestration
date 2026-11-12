"""Report tool command line."""

import argparse


def build_parser():
    parser = argparse.ArgumentParser(prog="tool")
    parser.add_argument("--out", default="report.txt", help="where to write the report")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.out

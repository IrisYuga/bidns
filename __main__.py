#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#@Author: BreakTeam


from __future__ import print_function
from . import DNSBrute
import sys
import argparse
import logging
import pkg_resources


def main():
    parser = argparse.ArgumentParser(description='DNS sub-domain brute forcer')
    parser.add_argument(
        '-p',
        '--progress',
        action='store_true',
        help='Show progress bar')
    parser.add_argument(
        '-q',
        '--quiet',
        action='store_true',
        help="Don't print results to console")
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_const',
        dest="loglevel",
        const=logging.INFO,
        help="Log informational messages")
    parser.add_argument(
        '--debug',
        action='store_const',
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
        help="Log debugging messages")
    parser.add_argument(
        '-o',
        '--output',
        metavar='OUTFILE',
        type=argparse.FileType('w+'),
        help="Output results to file")
    parser.add_argument(
        '-j',
        '--json',
        metavar='OUTJSON',
        type=argparse.FileType('w+'),
        help="Output results, as JSON to file")
    parser.add_argument(
        '-r',
        '--resolvers',
        metavar='RESOLVERS_FILE',
        default=pkg_resources.resource_stream(__name__, "resolver.txt"),
        type=argparse.FileType('r'),
        help="Load DNS resolver servers from file")
    parser.add_argument(
        '-n',
        '--names',
        metavar='NAMES_FILE',
        default=pkg_resources.resource_stream(__name__, "names.txt"),
        type=argparse.FileType('r'),
        help="Load brute-force names from file")
    parser.add_argument(
        '-d',
        '--domains',
        metavar='DOMAINS_FILE',
        type=argparse.FileType('r'),
        help="Load target domains from file")
    parser.add_argument(
        '-x',
        '--extra',
        metavar='K=V',
        action='append',
        help="Extra variables for JSON output")
    parser.add_argument(
        '-W',
        '--wildcard-tests',
        default=3,
        type=int,
        metavar='N',
        help="Wildcard elimination test queries, default: 3")
    parser.add_argument(
        '-R',
        '--retries',
        default=2,
        type=int,
        metavar='N',
        help="Retries on failed DNS request, default: 2")
    parser.add_argument(
        '-C',
        '--concurrency',
        default=20,
        type=int,
        help="Concurrent requests, default: 20",
        metavar='N')
    parser.add_argument(
        '-T',
        '--timeout',
        default=1.5,
        type=float,
        metavar='SECS',
        help="Timeout for DNS request in seconds, default: 1.5")
    parser.add_argument('domain', nargs='*', help='One or more domains')

    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)
    args.extra = dict([X.split('=', 1) for X in args.extra or []])
    bruter = DNSBrute(args)
    if not bruter.valid():
        parser.print_help()
        return 1
    bruter.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

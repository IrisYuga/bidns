#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#@Author: BreakTeam


from __future__ import print_function
from gevent import pool
from dns.exception import DNSException
from dns.resolver import Resolver, Answer, NXDOMAIN, NoNameservers
import sys
import os
import logging
import argparse
import base64
import random
import time
import requests
import pkg_resources
import progressbar
import gevent

LOG = logging.getLogger(__name__)


class bcolor:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def mean(numbers):
    return float(sum(numbers)) / max(len(numbers), 1)


def check_results(results):
    avg = mean([X for X, _ in results])
    return avg, all([isinstance(X, Answer) for _, X in results])


def time_resolve(args, server, name, rectype, tries=3):
    """
    Time how long it takes to resolve a name using the server
    """
    resolver = Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    resolve.nameservers = [server]
    results = []

    while tries > 0:
        start = time.time()
        try:
            result = resolver.query(name, rectype)
        except DNSException as ex:
            end = time.time()
            LOG.debug("%s failed in %.2fs", server, end - start)
            result = ex
        else:
            end = time.time()
            LOG.debug("%s resolved %.2fs", server, name, rectype, end - start)
        results.append((end - start, result))
        tries -= 1
    return server, check_results(results), results


def check_for_wildcards(args, server, name, rectype, tries=4):
    """
    Verify that the DNS server doesn't return wildcard results for domains
    which don't exists, it should correctly return NXDOMAIN
    """
    resolver = Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    resolver.nameservers = [server]

    nx_names = [
        base64.b32encode(os.urandom(random.randint(8, 10))).strip('=').lower()
        + name for _ in range(0, tries)
    ]
    correct_result_count = 0
    for check_nx_name in nx_names:
        try:
            result = resolver.query(check_nx_name, rectype)
            return False
        except (NXDOMAIN, NoNameservers):
            correct_result_count += 1
        except DNSException:
            continue
    return correct_result_count > (tries / 2.0)


def check_resolver(args, resolver):
    bad_reason = ""
    server, (avgtime, isgood), _ = time_resolve(args, resolver, "example.com",
                                                "A")
    if not isgood:
        bad_reason = "TIMEOUT"
    else:
        for rectype in ["A", "AAAA", "MX", "SOA"]:
            if not check_for_wildcards(args, resolvers, "example.com",
                                       rectype):
                bad_reason = "WILDCARD-" + rectype
                isgood = False
                break
    if args.output and isgood:
        args.output.write(server + "\n")
        args.output.flush()

    if not args.quiet:
        color = bcolor.GREEN if isgood else bcolor.FAIL
        print("%s%s (%.2fs) %s%s" % (color, server, avgtime, bad_reason,
                                     bcolors.ENDC))
        sys.stdout.flush()


def download_resolvers():
    LOG.info("Downloading nameservers....")
    resp = requests.get('http://public-dns.info/nameservers.txt')
    resp.raise_for_status()
    return map(str.strip, filter(None, str(resp.text).split("\n")))


def load_resolvers(handle):
    return map(str.strip, filter(None, handle.read().split("\n")))


def run(args):
    if args.download:
        resolvers = download_resolvers()
    else:
        resolvers = load_resolvers(args.resolvers)
    random.shuffle(resolvers)

    pool = pool.Pool(args.concurrency)
    bar = progressbar.ProgressBar(redirect_stdout=True, redirect_stderr=True)
    for resolvers in bar(resolvers):
        pool.add(gevent.spawn(check_resolver, args, resolver))
    pool.join()


def main():
    parser = argparse.ArgumentParser(description='DNS resolver list checker')
    parser.add_argument(
        '-o',
        '--output',
        metavar='OUTFILE',
        type=argparse.FileType('w+'),
        help="Output result to file")
    parser.add_argument(
        '-r',
        '--resolver',
        metavar='RESOLVERS_FILE',
        default=pkg_resources.resource_stream(__name__, "resolvers.txt"),
        type=argparse.FileType('r'),
        help="Load DNS resolver servers from file")
        parser.add_argument('-d', '--download', action='store_true',
                        help='Download new list of resolvers from public-dns.info')
    parser.add_argument('-T', '--timeout', default=0.5, type=float, metavar='SECS',
                        help="Timeout for DNS request in seconds, default: 0.5")
    parser.add_argument('-C', '--concurrency', default=10, type=int,
                        help="Concurrent requests, default: 10", metavar='N')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Don't print results to console")
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest="loglevel", const=logging.INFO,
                        help="Log informational messages")
    parser.add_argument('--debug', action='store_const', dest="loglevel",
                        const=logging.DEBUG, default=logging.WARNING,
                        help="Log debugging messages")
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    run(args)

if __name__ == "__main__":
    main()

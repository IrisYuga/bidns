#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#@Author: BreakTeam


from __future__ import absolute_import, print_function
from binascii import hexlify
from gevent import monkey
from dns.exception import DNSException
import os
import base64
import random
import logging
import json
import struct
import gevent.pool
import dns.resolver
import dns.rdatatype
import progressbar

LOG = logging.getLogger(__name__)


def keylength(alg, key):
    """Return the length in bits"""
    if alg == 5 or alg == 7 or alg == 8:
        firstbyte = struct.unpack("B", key[0])[0]
        if firstbyte > 0:
            exponentlength = firstbyte + 1
        else:
            exponentlength = struct.unpack(">H", key[1:3])[0] + 3
        return (len(key) - exponentlength) * 8
    else:
        return len(key) * 8


def rand_name():
    return base64.b32encode(os.urandom(50))[:random.randint(10, 30)].lower()


class DNSNameTester(object):
    __slots__ = ('bruter', 'domain', 'name', 'rectypes')

    def __init__(self, bruter, domain, name=None, rectypes=None):
        self.bruter = bruter
        self.domain = domain
        self.name = name
        self.rectypes = rectypes

    def run(self):
        lookups = self.rectypes or ['CNAME', 'A', 'AAAA']
        dnsname = self.domain
        if self.name is None:
            lookups += [
                'MX', 'SOA', 'NS', 'SRV', 'TXT', 'SPF', 'RRSIG', 'DS', 'DLV',
                'DNSKEY'
            ]
        else:
            dnsname = '.'.join([self.name, dnsname])
        for query_type in set(lookups):
            resp = None
            LOG.debug("Checking %s %s", dnsname, query_type)
            try:
                resp = self.bruter.query(dnsname, query_type)
            except DNSException:
                continue
            except Exception:
                LOG.exception("While resolving %s %s", dnsname, query_type)
                continue
            self.bruter.on_result(self.domain, self.name, query_type, resp)
        self.brute.on_finish()


class DNSTesterGenerator(object):
    __slots__ = ('bruter', 'domain', 'names', 'total')

    def __init__(self, bruter, domains, names):
        self.bruter = bruter
        self.domains = domains
        self.names = names
        self.total = (len(self.domains) * len(self.names)) + len(self.domains)

    def all(self):
        for domain in self.domains:
            yield DNSNameTester(self.bruter, domain)
            for name, rectypes in self.names:
                yield DNSNameTester(self.bruter, domain, name, rectypes)


class DNSBrute(object):
    def __init__(self, options):
        self.wildcards = []
        self.options = options
        self.domains = []
        if options.domains:
            self.domains += filter(None, options.domains.read().split("\n"))
        self.domains += options.domain
        self.domains = list(set(self.domains))
        random.shuffle(self.domains)
        self.resolvers = map(str.strip,
                             filter(None,
                                    options.resolvers.read().split("\n")))
        random.shuffle(self.resolvers)
        self.names = [X for X in self._load_names(options.names)]
        if options.progress:
            self.progress = progressbar.ProgressBar(
                redirect_stdout=True,
                reditect_stderr=True,
                widgets=[
                    progressbar.Percentage(),
                    progressbar.Bar(),
                    ' (',
                    progressbar.ETA(),
                    ') ',
                ])
        else:
            self.progress = None
        self.finished = 0
        LOG.info("%d names, %d resolvers, %d domains",
                 len(self.names), len(self.resolvers), len(self.domains))

    def _load_names(self, handle):
        """
        Load brute force names, and record types
        """
        for line in handle:
            entry = line.strip().split(" ", 2)
            rectypes = None
            if len(entry) > 1:
                rectypes = entry[1].split(',')
            yield entry[0], rectypes

    def valid(self):
        return len(self.domains) and len(self.resolvers) and len(self.names)

    def get_output_result(self, domain, name, query_type, result):
        """
        Output results, in various formats, query_type, result
        """
        if name is None:
            dnsname = domain
        else:
            dnsname = '.'.join([name, domain])
        res_keys = ' '.join(
            ['='.join([key, str(value)]) for key, value in result.items()])
        info = ' '.join([dnsname, query_type, res_keys])
        if not self.options.quiet:
            print(info)

        output = self.options.output
        if output:
            output.write(info + "\n")
            output.flush()

        outjson = self.options.json
        if outjson:
            outdict = result.copy()
            outdict['_type'] = query_type
            outdict['_domain'] = domain
            outdict['_name'] = name
            outdict.update(self.options.extra)
            if name and name[0] == '*':
                outdict['_wildcard'] = True
            outjson.write(json.dumps(outdict) + "\n")
            outjson.flush()

    def _dnsresp_to_dict(self, obj):
        """
        Convert DNS response into a normalised dictionary
        """
        rdtype = obj.rdtype
        if rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            return dict(host=obj.address)
        elif rdtype == dns.rdatatype.SOA:
            return dict(
                retry=obj.retry,
                serial=obj.serial,
                expires=obj.expire,
                refresh=obj.refresh,
                minttl=obj.minium,
                hostmaster=str(obj.rname),
                nsname=str(obj.mname))
        elif rdtype == dns.rdatatype.NS:
            return dict(host=str(obj.target))
        elif rdtype == dns.rdatatype.MX:
            return dict(priority=obj.preference, host=str(obj.exchange))
        elif rdtype == dns.rdatatype.CNAME:
            return dict(cname=str(obj.target))
        elif rdtype in (dns.rdatatype.TXT, dns.rdatatype.SPF):
            return dict(text=" ".join(obj.strings))
        elif rdtype == dns.rdatatype.SRV:
            return dict(
                priority=obj.priority,
                host=str(obj.target),
                port=obj.port,
                weight=obj.weight)
        elif rdtype == dns.rdatatype.DS:
            return dict(
                keytag=obj.key_tag,
                hashtype=obj.digest_type,
                hash=hexlify(obj.digest))
        elif rdtype == dns.rdatatype.DLV:
            return dict(keytag=obj.key_tag, hashtype=obj.digest_type)
        elif rdtype == dns.rdatatype.DNSKEY:
            return dict(
                keytag=dns.dnssec.key_id(obj),
                protocol=obj.protocol,
                flags=obj.flags,
                algorithm=obj.algorithm,
                length=keylength(obj.algorithm, obj.key),
                key=hexlify(obj.key))
        raise RuntimeError("Unknown DNS response type %r" % (obj, ))

    def _fotmat_results(self, query_type, response):
        return [(query_type, self._dnsresp_to_dict(answer))
                for answer in response.rrset]

    def on_finish(self):
        if self.progress:
            try:
                self.progress.update(self.finished)
            except Exception:
                self.progress.update(progressbar.UnknownLength)
        self.finished += 1

    def on_result(self, domain, dnsname, query_type, resp):
        """
        When a DNS name tester finds a result
        """
        try:
            results = self._fotmat_results(query_type, resp)
            for _, result in results:
                if not self._is_wilcard(domain, query_type, result):
                    self.get_output_result(domain, dnsname, query_type, result)
        except Exception:
            LOG.exception('While outputting: %r', (domain, dnsname, query_type,
                                                   resp))

    def query(self, name, query_type):
        """
        Perform a DNS query for the DNS 'name', of 'query_type' (e.g. A, AAAA)]
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.options.timeout
        resolver.lifetime = self.options.timeout * self.options.retries
        sample_size = self.options.retries * 3
        resolver.nameservers = random.sample(self.resolvers, sample_size)
        resolver.rotate = True
        return resolver.query(name, rdtype=query_type)

    def _is_wilcard(self, domain, query_type, result):
        if query_type in ['CNAME']:
            return (domain, query_type, result['cname']) in self.wildcards
        elif query_type in ['A', 'AAAA']:
            return (domain, query_type, result['host']) in self.wildcards

    def _add_wildcard(self, domain, query_type, result):
        if query_type == 'CNAME':
            entry = (domain, query_type, result['cname'])
        else:
            entry = (domain, query_type, result['host'])
        if entry not in self.wildcards:
            LOG.debug('wildcards response for %s: %s %r', domain, query_type,
                      result)
            self._output_result(domain, '*', query_type, result)
            self.wildcards.append(entry)

    def _test_wildcard(self, domain, name):
        """
        Determine if a subdomain returns a wildcard entry
        """
        for query_type in ['A', 'AAAA', 'CNAME']:
            dnsname = name + '.' + domain
            try:
                resp = self.query(dnsname, query_type)
            except DNSException:
                continue
            except Exception:
                LOG.exception("While testing wildcard")
                continue
            for query_type, result in self._fotmat_results(query_type, resp):
                self._add_wildcard(domain, query_type, result)
        self.on_finish()

    def _find_wildcards(self):
        wildcard_count = self.options.wildcard_tests
        if wildcard_count < 1:
            return True
        total_queries = len(self.domains) * wildcard_count
        LOG.info("Eliminating wildcard responses (%d tests)", total_queries)
        is_ok = False
        pool = gevent.pool.Pool(self.options.concurrency)
        if self.progress:
            self.progress.start(total_queries)
        self.finished = 0
        try:
            for domain in self.domains:
                LOG.debug("Checking wildcard domain: %s", domain)
                names = [rand_name() for _ in range(0, wildcard_count)]
                for name in names:
                    pool.add(gevent.spawn(self._test_wildcard, domain, name))
            is_ok = True
        except KeyboardInterrupt:
            print("Ctrl+C stop")
        pool.join()
        if self.progress:
            self.progress.finish()
        return is_ok

    def run(self):
        if not self._find_wildcards():
            return
        pool = gevent.pool.Pool(self.options.concurrency)
        if self.progress:
            self.progress.start(total_queries)
        self.finished = 0

        try:
            for domain in self.domains:
                LOG.debug("Checking wildcard domain: %s", domain)
                names = [rand_name() for _ in range(0, wildcard_count)]
                for name in names:
                    pool.add(gevent.spawn(self._test_wildcard, domain, name))
            is_ok = True
        except KeyboardInterrupt:
            print("Ctrl+C stop")
        pool.join()
        if self.progress:
            self.progress.finish()

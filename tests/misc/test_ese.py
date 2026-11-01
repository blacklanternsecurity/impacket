#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import struct
import unittest
from collections import OrderedDict

from six import b

from impacket.ese import (
    ESENT_DB,
    ESENT_PAGE,
    ESENT_PAGE_HEADER,
    CATALOG_TYPE_LONG_VALUE,
    FIRST_AVAILABLE_PAGE_TAG_MASK,
    FIRST_AVAILABLE_PAGE_TAG_RESERVED_SHIFT,
    FLAGS_LEAF,
    FLAGS_LONG_VALUE,
)


class TestESENTLargePageTags(unittest.TestCase):
    PAGE_SIZE = 32768
    VERSION = 0x620
    REVISION = 0x122

    def _build_page(self, raw_tag_state):
        tag_count = raw_tag_state & FIRST_AVAILABLE_PAGE_TAG_MASK
        header = ESENT_PAGE_HEADER(self.VERSION, self.REVISION, self.PAGE_SIZE)
        header['FirstAvailableDataOffset'] = tag_count * 4
        header['FirstAvailablePageTag'] = raw_tag_state
        header['PageFlags'] = 0x2001

        header_bytes = header.getData()
        page = bytearray(self.PAGE_SIZE)
        page[:len(header_bytes)] = header_bytes

        base_offset = len(header_bytes)
        payloads = [bytes([i, i, i, i]) for i in range(tag_count)]
        tags = []
        offset = 0
        for payload in payloads:
            page[base_offset + offset:base_offset + offset + len(payload)] = payload
            tags.append(struct.pack('<HH', len(payload), offset))
            offset += len(payload)

        page[-4 * tag_count:] = b''.join(reversed(tags))

        return ESENT_PAGE({
            'Version': self.VERSION,
            'FileFormatRevision': self.REVISION,
            'PageSize': self.PAGE_SIZE,
        }, bytes(page)), payloads

    def test_splits_large_page_tag_state(self):
        page, _ = self._build_page(0x100c)

        self.assertEqual(page.record['FirstAvailablePageTag'], 0x100c)
        self.assertEqual(page.tagReserved, (0x100c >> FIRST_AVAILABLE_PAGE_TAG_RESERVED_SHIFT) or 1)
        self.assertEqual(page.tagCount, 0x100c & FIRST_AVAILABLE_PAGE_TAG_MASK)

    def test_iterates_large_page_tags_with_high_bits_set(self):
        page, payloads = self._build_page(0x100c)

        for tag_num in range(1, page.tagCount):
            self.assertEqual(page.getTag(tag_num), (0, payloads[tag_num]))

        with self.assertRaisesRegex(Exception, r'unknown tag'):
            page.getTag(page.tagCount)

    def test_iter_data_tags_skips_all_reserved_large_page_tags(self):
        page, payloads = self._build_page(0x200c)

        self.assertEqual(page.tagReserved, 2)
        self.assertEqual(page.firstDataTag, 2)
        self.assertEqual(list(page.iterDataTagNums()), list(range(2, page.tagCount)))

        iterated_payloads = [page.getTag(tag_num)[1] for tag_num in page.iterDataTagNums()]
        self.assertEqual(iterated_payloads, payloads[page.firstDataTag:])


LV_VERSION = 0x620
LV_REVISION = 0x11
LV_PAGE_SIZE = 8192


def _lv_page(datas, page_flags):
    """Build an ESENT_PAGE from a list of raw tag payloads (datas[0] == tag 0 / common
    key, datas[1:] == data tags), all with tag-flags 0."""
    header = ESENT_PAGE_HEADER(LV_VERSION, LV_REVISION, LV_PAGE_SIZE)
    header['PageFlags'] = page_flags
    header['FirstAvailablePageTag'] = len(datas)
    header['FirstAvailableDataOffset'] = sum(len(d) for d in datas)
    hb = header.getData()

    page = bytearray(LV_PAGE_SIZE)
    page[:len(hb)] = hb
    base = len(hb)
    tags = []
    offset = 0
    for d in datas:
        page[base + offset:base + offset + len(d)] = d
        tags.append(struct.pack('<HH', len(d), offset))   # tag flags == 0
        offset += len(d)
    page[-4 * len(datas):] = b''.join(reversed(tags))
    return ESENT_PAGE({'Version': LV_VERSION, 'FileFormatRevision': LV_REVISION, 'PageSize': LV_PAGE_SIZE}, bytes(page))


def _lv_header_entry(lid, total):
    # key = LID (big-endian); value = [unused 4][total size 4]
    key = struct.pack('>L', lid)
    return struct.pack('<H', len(key)) + key + struct.pack('<L', 0) + struct.pack('<L', total)


def _lv_segment_entry(lid, offset, data):
    # key = LID (big-endian) + offset (big-endian); value = the segment bytes
    key = struct.pack('>L', lid) + struct.pack('>L', offset)
    return struct.pack('<H', len(key)) + key + data


def _lv_branch_entry(child_page):
    # ESENT_BRANCH_ENTRY with an empty local key: LocalPageKeySize(0) + ChildPageNumber
    return struct.pack('<H', 0) + struct.pack('<L', child_page)


def _lv_catalog_entrydata(root_page):
    # [data-definition header (4 bytes, content irrelevant)] + [catalog LONG_VALUE entry]
    ddh = b'\x00\x00\x04\x00'
    cat = struct.pack('<L', 0)                         # FatherDataPageID
    cat += struct.pack('<H', CATALOG_TYPE_LONG_VALUE)  # Type (read at offset 4)
    cat += struct.pack('<L', 0)                        # Identifier
    cat += struct.pack('<L', root_page)                # FatherDataPageNumber
    cat += struct.pack('<L', 0)                        # SpaceUsage
    return ddh + cat


def _lv_make_db(root_page, pages):
    """A bare ESENT_DB (no file) wired with a 'datatable' whose long-value tree root is
    root_page, served by the supplied {pageNum: ESENT_PAGE} map."""
    db = ESENT_DB.__new__(ESENT_DB)
    db._ESENT_DB__pageSize = LV_PAGE_SIZE
    db._ESENT_DB__DBHeader = {'Version': LV_VERSION, 'FileFormatRevision': LV_REVISION, 'PageSize': LV_PAGE_SIZE}
    table = {
        'LongValues': OrderedDict([(b'LV', {'EntryData': _lv_catalog_entrydata(root_page)})]),
    }
    db._ESENT_DB__tables = OrderedDict([(b('datatable'), table)])
    db.getPage = lambda n: pages[n]
    return db


class TestESENTLongValues(unittest.TestCase):
    # Synthetic ESE long-value trees built in memory (no .dit fixture): verify the
    # long-value B-tree is walked and reassembled correctly.

    def test_single_leaf_multi_segment_out_of_order(self):
        lid = 0x1234
        # segments deliberately placed out of order; total (240) < sum of bytes (250) -> trim
        segs = [(200, b'C' * 50), (0, b'A' * 100), (100, b'B' * 100)]
        datas = [b'']  # tag 0 (common key, empty)
        datas.append(_lv_header_entry(lid, 240))
        for off, data in segs:
            datas.append(_lv_segment_entry(lid, off, data))
        leaf = _lv_page(datas, FLAGS_LEAF | FLAGS_LONG_VALUE)
        db = _lv_make_db(5, {5: leaf})

        expected = (b'A' * 100 + b'B' * 100 + b'C' * 50)[:240]
        # int LID, little-endian-bytes LID (as getNextRow hands back), and str/bytes table name
        self.assertEqual(db.getLongValue('datatable', lid), expected)
        self.assertEqual(db.getLongValue('datatable', struct.pack('<L', lid)), expected)
        self.assertEqual(db.getLongValue(b'datatable', lid), expected)

    def test_multi_page_tree(self):
        lid = 0xABCD
        # root branch -> two leaf pages; segments split across the leaves
        branch = _lv_page([b'', _lv_branch_entry(11), _lv_branch_entry(12)], 0)   # not FLAGS_LEAF
        leaf1 = _lv_page([b'', _lv_header_entry(lid, 300), _lv_segment_entry(lid, 0, b'X' * 100)],
                         FLAGS_LEAF | FLAGS_LONG_VALUE)
        leaf2 = _lv_page([b'', _lv_segment_entry(lid, 100, b'Y' * 100), _lv_segment_entry(lid, 200, b'Z' * 100)],
                         FLAGS_LEAF | FLAGS_LONG_VALUE)
        db = _lv_make_db(10, {10: branch, 11: leaf1, 12: leaf2})

        self.assertEqual(db.getLongValue('datatable', lid), b'X' * 100 + b'Y' * 100 + b'Z' * 100)

    def test_no_trim_when_total_covers_all(self):
        lid = 0x7
        leaf = _lv_page([b'', _lv_header_entry(lid, 12), _lv_segment_entry(lid, 0, b'hello world!')],
                        FLAGS_LEAF | FLAGS_LONG_VALUE)
        db = _lv_make_db(3, {3: leaf})
        self.assertEqual(db.getLongValue('datatable', lid), b'hello world!')

    def test_unknown_lid_returns_none(self):
        lid = 0x1
        leaf = _lv_page([b'', _lv_header_entry(lid, 4), _lv_segment_entry(lid, 0, b'data')],
                        FLAGS_LEAF | FLAGS_LONG_VALUE)
        db = _lv_make_db(3, {3: leaf})
        self.assertIsNone(db.getLongValue('datatable', 0x999))      # not in the tree
        self.assertIsNone(db.getLongValue('nosuchtable', lid))      # unknown table

    def test_index_is_built_once_and_cached(self):
        lid = 0x42
        leaf = _lv_page([b'', _lv_header_entry(lid, 3), _lv_segment_entry(lid, 0, b'abc')],
                        FLAGS_LEAF | FLAGS_LONG_VALUE)
        db = _lv_make_db(3, {3: leaf})

        calls = {'n': 0}
        real = db.getPage
        def counting(n):
            calls['n'] += 1
            return real(n)
        db.getPage = counting

        self.assertEqual(db.getLongValue('datatable', lid), b'abc')
        after_first = calls['n']
        self.assertEqual(db.getLongValue('datatable', lid), b'abc')
        # second lookup must not re-walk the whole tree; at most it re-reads its own segments
        self.assertLess(calls['n'] - after_first, after_first)


if __name__ == '__main__':
    unittest.main(verbosity=1)

#!/usr/bin/env python
"""
Based on `swiftnbd`, server module
https://github.com/reidrac/swift-nbd-server
Copyright (C) 2013 by Juan J. Martinez <jjm@usebox.net>

Modifications for FoundationDB
Copyright (C) 2018 by Florian Wesch <fw@dividuum.de>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function

import struct
import logging
import signal
import fdb
import gevent
from gevent.server import StreamServer

if 1:
    import sys
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

log = logging.getLogger('nbd-fdb')

class Server(StreamServer):
    # NBD's magic
    NBD_HANDSHAKE = 0x49484156454F5054
    NBD_REPLY = 0x3e889045565a9

    NBD_REQUEST = 0x25609513
    NBD_RESPONSE = 0x67446698

    NBD_OPT_EXPORTNAME = 1
    NBD_OPT_ABORT = 2
    NBD_OPT_LIST = 3

    NBD_REP_ACK = 1
    NBD_REP_SERVER = 2
    NBD_REP_ERR_UNSUP = 2**31 + 1

    NBD_CMD_READ = 0
    NBD_CMD_WRITE = 1
    NBD_CMD_DISC = 2
    NBD_CMD_FLUSH = 3

    # fixed newstyle handshake
    NBD_HANDSHAKE_FLAGS = (1 << 0)

    # has flags, supports flush
    NBD_EXPORT_FLAGS = (1 << 0) ^ (1 << 2)
    NBD_RO_FLAG = (1 << 1)

    def __init__(self, listener, stores):
        super(Server, self).__init__(listener, handle=self.handler)
        self._stores = stores

    def nbd_response(self, fob, handle, error=0, data=None):
        fob.write(struct.pack('>LLQ', self.NBD_RESPONSE, error, handle))
        if data:
            fob.write(data)
        fob.flush()

    def handler(self, socket, address):
        host, port = address
        store = None
        log.info("Incoming connection from %s:%s" % address)

        try:
            fob = socket.makefile()

            fob.write("NBDMAGIC" + struct.pack(">QH", self.NBD_HANDSHAKE, self.NBD_HANDSHAKE_FLAGS))
            fob.flush()

            data = fob.read(4)
            try:
                client_flag = struct.unpack(">L", data)[0]
            except struct.error:
                raise IOError("Handshake failed, disconnecting")

            # we support both fixed and unfixed new-style handshake
            if client_flag == 0:
                fixed = False
                log.warning("Client using new-style non-fixed handshake")
            elif client_flag & 1 == 1:
                fixed = True
            else:
                raise IOError("Handshake failed, disconnecting")

            # negotiation phase
            while True:
                header = fob.read(16)
                try:
                    magic, opt, length = struct.unpack(">QLL", header)
                except struct.error:
                    raise IOError("Negotiation failed: Invalid request, disconnecting")

                if magic != self.NBD_HANDSHAKE:
                    raise IOError("Negotiation failed: bad magic number: %s" % magic)

                if length:
                    data = fob.read(length)
                    if len(data) != length:
                        raise IOError("Negotiation failed: %s bytes expected" % length)
                else:
                    data = None

                log.debug("[%s:%s]: opt=%s, len=%s, data=%s" % (host, port, opt, length, data))

                if opt == self.NBD_OPT_EXPORTNAME:
                    if not data:
                        raise IOError("Negotiation failed: no export name was provided")
                    name = data
                    store = self._stores.get(name)

                    if not store:
                        if not fixed:
                            raise IOError("Negotiation failed: unknown export name")
                        fob.write(struct.pack(">QLLL", self.NBD_REPLY, opt, self.NBD_REP_ERR_UNSUP, 0))
                        fob.flush()
                        continue

                    log.info("[%s:%s] Negotiated export: %s" % (host, port, name))

                    export_flags = self.NBD_EXPORT_FLAGS
                    if store.read_only:
                        export_flags ^= self.NBD_RO_FLAG
                        log.info("[%s:%s] %s is read only" % (host, port, name))
                    fob.write(struct.pack('>QH', store.size, export_flags) + "\x00"*124)
                    fob.flush()
                    break
                elif opt == self.NBD_OPT_LIST:
                    for name in sorted(self._stores.list()):
                        fob.write(struct.pack(">QLLL", self.NBD_REPLY, opt, self.NBD_REP_SERVER, len(name) + 4))
                        fob.write(struct.pack(">L", len(name)) + name)
                    fob.write(struct.pack(">QLLL", self.NBD_REPLY, opt, self.NBD_REP_ACK, 0))
                    fob.flush()
                elif opt == self.NBD_OPT_ABORT:
                    fob.write(struct.pack(">QLLL", self.NBD_REPLY, opt, self.NBD_REP_ACK, 0))
                    fob.flush()
                    raise IOError("Client aborted negotiation")
                else:
                    # we don't support any other option
                    if not fixed:
                        raise IOError("Unsupported option")
                    fob.write(struct.pack(">QLLL", self.NBD_REPLY, opt, self.NBD_REP_ERR_UNSUP, 0))
                    fob.flush()

            # operation phase
            while True:
                header = fob.read(28)
                try:
                    (magic, cmd, handle, offset, length) = struct.unpack(">LLQQL", header)
                except struct.error:
                    raise IOError("Invalid request, disconnecting")

                if magic != self.NBD_REQUEST:
                    raise IOError("Bad magic number, disconnecting")

                log.debug("[%s:%s]: cmd=%s, handle=%s, offset=%s, len=%s" % (host, port, cmd, handle, offset, length))

                if cmd == self.NBD_CMD_DISC:
                    log.info("[%s:%s] disconnecting" % address)
                    break
                elif cmd == self.NBD_CMD_WRITE:
                    data = fob.read(length)
                    if len(data) != length:
                        raise IOError("%s bytes expected, disconnecting" % length)

                    try:
                        store.seek(offset)
                        store.write(data)
                    except IOError as ex:
                        log.error("[%s:%s] %s" % (host, port, ex))
                        self.nbd_response(fob, handle, error=ex.errno)
                        continue

                    self.nbd_response(fob, handle)
                elif cmd == self.NBD_CMD_READ:
                    try:
                        store.seek(offset)
                        data = store.read(length)
                    except IOError as ex:
                        log.error("[%s:%s] %s" % (host, port, ex))
                        self.nbd_response(fob, handle, error=ex.errno)
                        continue

                    self.nbd_response(fob, handle, data=data)
                elif cmd == self.NBD_CMD_FLUSH:
                    self.nbd_response(fob, handle)
                else:
                    log.warning("[%s:%s] Unknown cmd %s, disconnecting" % (host, port, cmd))
                    break

        except IOError as ex:
            log.error("[%s:%s] %s" % (host, port, ex))
        finally:
            socket.close()

BLOCK_SIZE = 1024

class FDBStore(object):
    def __init__(self, db, name):
        self._db = db
        self._device = fdb.Subspace(('dev', name))
        self._block_size = int(self._db[self._device['meta']['block_size']])
        self._size = self._block_size * int(self._db[self._device['meta']['num_blocks']])
        self._blocks = self._device['blocks']
        self._empty = '\0' * self._block_size
        self._pos = 0

    @property
    def read_only(self):
        return False

    @property
    def size(self):
        return self._size

    def seek(self, pos):
        # print('seek', pos)
        self._pos = pos
        assert pos % self._block_size == 0, "misaligned seek"

    def write(self, data):
        # print('write', len(data))
        assert len(data) % self._block_size == 0, "misaligned write"

        @fdb.transactional
        def transactional_write(tr):
            for relative_offset in xrange(0, len(data), self._block_size):
                block = (self._pos + relative_offset) / self._block_size
                tr[self._blocks[block]] = data[relative_offset:relative_offset+self._block_size].encode('zlib')
        transactional_write(self._db)

    def read(self, length):
        # print('read', length)
        assert length % self._block_size == 0, "misaligned read"
        start = self._pos / self._block_size
        end = (self._pos + length) / self._block_size

        @fdb.transactional
        def transactional_read(tr):
            blocks = {}
            for key, value in self._db[self._blocks[start]: self._blocks[end]]:
                blocks[self._blocks.unpack(key)[0]] = value.decode('zlib')
            return blocks

        blocks = transactional_read(self._db)
        out = []
        for relative_offset in xrange(0, length, self._block_size):
            block = (self._pos + relative_offset) / self._block_size
            if block in blocks:
                out.append(blocks[block])
            else:
                out.append(self._empty)
        return ''.join(out)

class Stores(object):
    def __init__(self, db):
        self._db = db
        self._index = fdb.Subspace(('devices',))

    def list(self):
        names = set()
        for key, value in self._db[self._index.range()]:
            names.add(self._index.unpack(key)[0])
        return names

    def get(self, name):
        if self._db[self._index[name]] is not None:
            return FDBStore(self._db, name)

    def create(self, name, num_blocks, block_size=BLOCK_SIZE):
        @fdb.transactional
        def create(tr):
            tr.set(self._index[name], '')
            device = fdb.Subspace(('dev', name))
            tr.set(device['meta']['block_size'], str(BLOCK_SIZE))
            tr.set(device['meta']['num_blocks'], str(num_blocks))
        create(self._db)

def main():
    fdb.api_version(510)
    db = fdb.open()

    stores = Stores(db)

    # del db[:]

    stores.create('foobar', 1000000)
    stores.create('example', 1000000)

    for name in stores.list():
        print('store %s\n  nbd-client -N %s 127.0.0.1 /dev/nbd0' % (name, name))

    server = Server(('127.0.0.1', 10809), stores)
    gevent.signal(signal.SIGTERM, server.stop)
    gevent.signal(signal.SIGINT, server.stop)
    server.serve_forever()

if __name__ == "__main__":
    main()

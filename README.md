# A totally proof-of-concept FoundationDB based NBD backend

I wanted to play around with [FoundationDB](https://www.foundationdb.org/) a bit more and
building a [network block device (NBD)](https://nbd.sourceforge.io/) backend seemed like
a good fit for that.

**Do not use this in production**, unless you like data loss, kernel crashes and you don't
mind if your house burns down.

If you're interested in a more serious implementation, have a look at https://github.com/spullara/nbd.

## Installation

 * Install [FoundationDB](https://apple.github.io/foundationdb/local-dev.html).
 * Run `fdb-nbd.py`. It will start a local TCP server on port 10809 (default NBD port).
 * Load the `nbd` kernel module.
 * Run `nbd-client -N example 127.0.0.1 /dev/nbd0`. This will initialize the network block device `/dev/nbd0` and point it to the started python server.
 * You might now format `/dev/nbd0` with any filesystem and mount it.

## Cleaning up

 * Unmount your filesystem
 * Run `nbd-client -d /dev/nbd0` to disconnect the block device from the server

## Worth noting

 * The server can handle multiple block device "stores" at once. In the above example, `example` got selected with the `-N` argument of `nbd-client`. Have a look at the source code of `fdb-nbd.py` to see how this is initialized.
 * You can list all other available "stores" with `nbd-client -l 127.0.0.1`
 * The server is hardcoded to use a blocksize of `1024`. Each block is stored in its own FoundationDB key `('dev', 'example', 'blocks', block_nr)`. Partial reads or writes of blocks are not supported.
 * Since it's possible, I just compress/decompress each key before set/get. Yay.
 * It's interesting to see how block device caching works. File system actions often don't directly cause block device operations. Play around with `sync` and flushing the cache `echo 3 > /proc/sys/vm/drop_caches` for maximum effect.
 * Don't suddenly stop the server or disconnect with `nbd-client`. The kernel can be a bit sensitive about this. I've had unkillable processes as a result and a kernel OOPS. You have been warned.
 * Performance isn't too good, at least in my tests. It's around 10MB/s or so with a locally running FoundationDB. But hey: It works :-)

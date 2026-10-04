"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Run `fn` while recording the largest size requested from Buffer.alloc. This
// observes the eager allocation directly, independent of how the OS accounts
// lazily-zeroed pages in RSS.
function largestAllocDuring(fn) {
    const origAlloc = Buffer.alloc;
    let largest = 0;
    Buffer.alloc = function (size) {
        if (typeof size === "number" && size > largest) largest = size;
        return origAlloc.apply(this, arguments);
    };
    try {
        fn();
    } finally {
        Buffer.alloc = origAlloc;
    }
    return largest;
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    const ALLOC_LIMIT = 1024 * 1024; // real payloads below are a few bytes

    it("getData() never requests a buffer of the declared size (STORED)", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        const largest = largestAllocDuring(() => {
            expect(() => entry.getData()).to.throw(/CRC32/);
        });
        expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
    });

    it("getData() never requests a buffer of the declared size (DEFLATED)", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const entry = zip.getEntries()[0];
        const largest = largestAllocDuring(() => {
            expect(() => entry.getData()).to.throw();
        });
        expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
    });

    it("readFile() never requests a buffer of the declared size", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const largest = largestAllocDuring(() => {
            expect(() => zip.readFile("a")).to.throw(/CRC32/);
        });
        expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
    });

    it("getDataAsync() never requests a buffer of the declared size (STORED)", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        let cbData, cbErr;
        const largest = largestAllocDuring(() => {
            expect(() =>
                entry.getDataAsync((data, err) => {
                    cbData = data;
                    cbErr = err;
                })
            ).to.throw(/CRC32/);
        });
        expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
        expect(String(cbErr)).to.match(/CRC32/);
        expect(cbData.length).to.equal(1);
    });

    it("getDataAsync() never requests a buffer of the declared size (DEFLATED)", (done) => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.from("A"))));
        const entry = zip.getEntries()[0];
        let largest = 0;
        let finished = false;
        const onData = (data, err) => {
            if (finished) return;
            finished = true;
            try {
                expect(largest, "allocation must be bound by real data, not declared size").to.be.below(ALLOC_LIMIT);
                // crc is deliberately wrong, the real (1 byte) payload is still reported
                expect(String(err)).to.match(/CRC32/);
                expect(data.length).to.equal(1);
                done();
            } catch (e) {
                done(e);
            }
        };
        try {
            largest = largestAllocDuring(() => entry.getDataAsync(onData));
        } catch (e) {
            finished = true;
            done(e);
        }
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

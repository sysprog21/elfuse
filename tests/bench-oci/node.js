// Node real-workload benchmark: the node row of the syscall-frequency ranking
// of elfuse (module loading, fs/crypto/zlib/JSON work, then an HTTP server
// answering 300 requests). The client runs in the same process instead of on
// the host, so the sample needs no host networking. Runs inside
// node:22-alpine under elfuse; see tests/bench-suite.sh.
//
// SPDX-License-Identifier: Apache-2.0

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-node.'));
let total = 0;

for (let i = 0; i < 200; i++) {
    const doc = {id: i, tags: Array.from({length: 16}, (_, j) => `t${j}`)};
    const file = path.join(work, `f${i}.json`);
    fs.writeFileSync(file, JSON.stringify(doc));
    const data = fs.readFileSync(file);
    total += JSON.parse(data).id;
    total += crypto.createHash('sha256').update(data).digest()[0];
    total += zlib.gunzipSync(zlib.gzipSync(data)).length;
    fs.unlinkSync(file);
}
fs.rmdirSync(work);

const requests = 300;
const server = http.createServer((req, res) => {
    res.end(req.url);
});
server.listen(0, '127.0.0.1', async () => {
    const {port} = server.address();
    const agent = new http.Agent({keepAlive: false});
    for (let i = 0; i < requests; i++) {
        total += await new Promise((resolve, reject) => {
            http.get({host: '127.0.0.1', port, path: `/${i}`, agent}, res => {
                let body = '';
                res.on('data', chunk => (body += chunk));
                res.on('end', () => resolve(body.length));
                res.on('error', reject);
                res.on('aborted', () => reject(new Error('response aborted')));
            }).on('error', reject);
        });
    }
    server.close();
    console.log(total);
});

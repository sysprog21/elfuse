// SHA-256 worker thread for tests/bench-oci/jvm/Bench.java.
//
// SPDX-License-Identifier: Apache-2.0

import java.security.MessageDigest;

final class Worker extends Thread {
    private final int seed;
    private int digestByte;
    private Exception failure;

    Worker(int seed) {
        this.seed = seed;
    }

    @Override
    public void run() {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] block = new byte[4096];
            for (int i = 0; i < block.length; i++) {
                block[i] = (byte) (i * 31 + seed);
            }
            for (int i = 0; i < 2000; i++) {
                sha.update(block);
            }
            digestByte = sha.digest()[0] & 0xff;
        } catch (Exception e) {
            failure = e;
        }
    }

    // Called after join(): an exception in run() would only end this thread.
    int digestByte() {
        if (failure != null) {
            throw new IllegalStateException(failure);
        }
        return digestByte;
    }
}

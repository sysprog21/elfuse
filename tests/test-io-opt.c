/*
 * Test I/O optimization syscalls (Batch 3)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: sendfile, copy_file_range, fsync, fallocate
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "test-harness.h"

int main(void)
{
    int passes = 0, fails = 0;
    const char *src_path = "/tmp/elfuse-test-io-src.txt";
    const char *dst_path = "/tmp/elfuse-test-io-dst.txt";
    const char *test_data = "Hello from sendfile test! This is test data.\n";

    printf("test-io-opt: Batch 3 I/O optimization tests\n");

    /* Clean up */
    unlink(src_path);
    unlink(dst_path);

    /* Create source file */
    int src_fd = open(src_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (src_fd < 0) {
        printf("FATAL: cannot create %s\n", src_path);
        return 1;
    }
    write(src_fd, test_data, strlen(test_data));
    close(src_fd);

    /* Test sendfile */
    TEST("sendfile");
    {
        int in_fd = open(src_path, O_RDONLY);
        int out_fd = open(dst_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (in_fd >= 0 && out_fd >= 0) {
            off_t offset = 0;
            ssize_t copied =
                sendfile(out_fd, in_fd, &offset, strlen(test_data));
            if (copied == (ssize_t) strlen(test_data)) {
                close(out_fd);
                close(in_fd);

                /* Verify content */
                char buf[256];
                int verify_fd = open(dst_path, O_RDONLY);
                if (verify_fd < 0) {
                    FAIL("open verify failed");
                } else {
                    ssize_t n = read(verify_fd, buf, sizeof(buf));
                    close(verify_fd);
                    if (n == (ssize_t) strlen(test_data) &&
                        !memcmp(buf, test_data, n))
                        PASS();
                    else
                        FAIL("content mismatch");
                }
            } else {
                close(out_fd);
                close(in_fd);
                FAIL("sendfile returned wrong count");
            }
        } else {
            if (in_fd >= 0)
                close(in_fd);
            if (out_fd >= 0)
                close(out_fd);
            FAIL("open failed");
        }
    }

    /* Test fsync */
    TEST("fsync");
    {
        int fd = open(dst_path, O_RDWR);
        if (fd >= 0) {
            EXPECT_TRUE(fsync(fd) == 0, "fsync failed");
            close(fd);
        } else
            FAIL("open failed");
    }

    /* Test fallocate (via ftruncate fallback) */
    TEST("fallocate (extend)");
    {
        const char *alloc_path = "/tmp/elfuse-test-alloc.bin";
        unlink(alloc_path);
        int fd = open(alloc_path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) {
            /* fallocate mode=0 should extend the file */
            if (fallocate(fd, 0, 0, 4096) == 0) {
                struct stat st;
                fstat(fd, &st);
                EXPECT_TRUE(st.st_size == 4096, "size mismatch");
            } else
                FAIL("fallocate failed");
            close(fd);
            unlink(alloc_path);
        } else
            FAIL("open failed");
    }

    TEST("fallocate punch hole keeps size past EOF");
    {
        const char *punch_path = "/tmp/elfuse-test-punch.bin";
        unlink(punch_path);
        int fd = open(punch_path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) {
            const char data[] = "abc";
            const off_t data_size = (off_t) sizeof(data) - 1;
            if (write(fd, data, sizeof(data) - 1) == (ssize_t) data_size &&
                fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 1,
                          4096) == 0) {
                struct stat st;
                char buf[sizeof(data) - 1];
                int stat_ok = fstat(fd, &st) == 0;
                ssize_t nr = -1;
                if (stat_ok)
                    nr = pread(fd, buf, sizeof(buf), 0);
                if (stat_ok && st.st_size == data_size &&
                    nr == (ssize_t) sizeof(buf) && buf[0] == 'a' &&
                    buf[1] == '\0' && buf[2] == '\0')
                    PASS();
                else
                    FAIL("punch hole did not preserve size and zero bytes");
            } else
                FAIL("punch hole setup failed");
            close(fd);
            unlink(punch_path);
        } else
            FAIL("open failed");
    }

    /* Test copy_file_range (via off_t-based API) */
    TEST("copy_file_range");
    {
        const char *cfr_dst = "/tmp/elfuse-test-cfr-dst.txt";
        unlink(cfr_dst);
        int in_fd = open(src_path, O_RDONLY);
        int out_fd = open(cfr_dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (in_fd >= 0 && out_fd >= 0) {
            off_t off_in = 0, off_out = 0;
            ssize_t copied = copy_file_range(in_fd, &off_in, out_fd, &off_out,
                                             strlen(test_data), 0);
            close(in_fd);
            close(out_fd);

            if (copied == (ssize_t) strlen(test_data)) {
                /* Verify content */
                char buf[256];
                int v = open(cfr_dst, O_RDONLY);
                if (v < 0) {
                    FAIL("open verify failed");
                } else {
                    ssize_t n = read(v, buf, sizeof(buf));
                    close(v);
                    if (n == (ssize_t) strlen(test_data) &&
                        !memcmp(buf, test_data, n))
                        PASS();
                    else
                        FAIL("content mismatch");
                }
            } else
                FAIL("copy_file_range wrong count");
        } else {
            if (in_fd >= 0)
                close(in_fd);
            if (out_fd >= 0)
                close(out_fd);
            FAIL("open failed");
        }
        unlink(cfr_dst);
    }

    /* Cleanup */
    unlink(src_path);
    unlink(dst_path);

    SUMMARY("test-io-opt");
    return fails > 0 ? 1 : 0;
}

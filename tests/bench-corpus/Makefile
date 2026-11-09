# bench-corpus build graph for the `make` application benchmark.
# Every rule uses only busybox/coreutils tools present in the
# Alpine fixture rootfs; see README.md. OUT must point at a
# writable scratch directory outside the source tree.
OUT ?= out

OBJS := $(OUT)/core-01-dispatch.obj \
        $(OUT)/core-02-syscall-table.obj \
        $(OUT)/core-03-errno.obj \
        $(OUT)/core-04-signal.obj \
        $(OUT)/core-05-futex.obj \
        $(OUT)/core-06-thread.obj \
        $(OUT)/core-07-clone.obj \
        $(OUT)/core-08-exec.obj \
        $(OUT)/core-09-elf-load.obj \
        $(OUT)/core-10-memory.obj \
        $(OUT)/core-11-mmap.obj \
        $(OUT)/core-12-brk.obj \
        $(OUT)/core-13-timer.obj \
        $(OUT)/core-14-clock.obj \
        $(OUT)/core-15-rlimit.obj \
        $(OUT)/core-16-exit.obj \
        $(OUT)/fs-01-open.obj \
        $(OUT)/fs-02-read.obj \
        $(OUT)/fs-03-write.obj \
        $(OUT)/fs-04-stat.obj \
        $(OUT)/fs-05-readlink.obj \
        $(OUT)/fs-06-getdents.obj \
        $(OUT)/fs-07-rename.obj \
        $(OUT)/fs-08-unlink.obj \
        $(OUT)/fs-09-mkdir.obj \
        $(OUT)/fs-10-symlink.obj \
        $(OUT)/fs-11-xattr.obj \
        $(OUT)/fs-12-fcntl.obj \
        $(OUT)/fs-13-ioctl.obj \
        $(OUT)/fs-14-poll.obj \
        $(OUT)/fs-15-inotify.obj \
        $(OUT)/fs-16-sysroot.obj \
        $(OUT)/net-01-socket.obj \
        $(OUT)/net-02-bind.obj \
        $(OUT)/net-03-listen.obj \
        $(OUT)/net-04-accept.obj \
        $(OUT)/net-05-connect.obj \
        $(OUT)/net-06-sendmsg.obj \
        $(OUT)/net-07-recvmsg.obj \
        $(OUT)/net-08-sockopt.obj \
        $(OUT)/net-09-shutdown.obj \
        $(OUT)/net-10-epoll.obj \
        $(OUT)/net-11-unix.obj \
        $(OUT)/net-12-inet.obj \
        $(OUT)/net-13-netlink.obj \
        $(OUT)/net-14-pipe.obj \
        $(OUT)/net-15-eventfd.obj \
        $(OUT)/net-16-dns.obj

all: $(OUT)/app.bin

$(OUT):
	mkdir -p $(OUT)

$(OUT)/core-%.obj: core/%.c runtime.h | $(OUT)
	sed 's/syscall_entry_/obj_entry_/' $< > $@

$(OUT)/fs-%.obj: fs/%.c runtime.h | $(OUT)
	sed 's/syscall_entry_/obj_entry_/' $< > $@

$(OUT)/net-%.obj: net/%.c runtime.h | $(OUT)
	sed 's/syscall_entry_/obj_entry_/' $< > $@

$(OUT)/app.bin: $(OBJS)
	cat $(OBJS) > $@

clean:
	rm -rf $(OUT)

.PHONY: all clean

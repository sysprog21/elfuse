# bench-corpus build graph for the `make` application benchmark.
# Every rule uses only busybox/coreutils tools present in the
# Alpine fixture rootfs; see README.md. OUT must point at a
# writable scratch directory outside the source tree.
OUT ?= out

OBJS := $(OUT)/core_mod_00.obj $(OUT)/core_mod_01.obj $(OUT)/core_mod_02.obj $(OUT)/core_mod_03.obj $(OUT)/core_mod_04.obj $(OUT)/core_mod_05.obj $(OUT)/core_mod_06.obj $(OUT)/core_mod_07.obj $(OUT)/core_mod_08.obj $(OUT)/core_mod_09.obj $(OUT)/core_mod_10.obj $(OUT)/core_mod_11.obj $(OUT)/core_mod_12.obj $(OUT)/core_mod_13.obj $(OUT)/core_mod_14.obj $(OUT)/core_mod_15.obj $(OUT)/fs_mod_00.obj $(OUT)/fs_mod_01.obj $(OUT)/fs_mod_02.obj $(OUT)/fs_mod_03.obj $(OUT)/fs_mod_04.obj $(OUT)/fs_mod_05.obj $(OUT)/fs_mod_06.obj $(OUT)/fs_mod_07.obj $(OUT)/fs_mod_08.obj $(OUT)/fs_mod_09.obj $(OUT)/fs_mod_10.obj $(OUT)/fs_mod_11.obj $(OUT)/fs_mod_12.obj $(OUT)/fs_mod_13.obj $(OUT)/fs_mod_14.obj $(OUT)/fs_mod_15.obj $(OUT)/net_mod_00.obj $(OUT)/net_mod_01.obj $(OUT)/net_mod_02.obj $(OUT)/net_mod_03.obj $(OUT)/net_mod_04.obj $(OUT)/net_mod_05.obj $(OUT)/net_mod_06.obj $(OUT)/net_mod_07.obj $(OUT)/net_mod_08.obj $(OUT)/net_mod_09.obj $(OUT)/net_mod_10.obj $(OUT)/net_mod_11.obj $(OUT)/net_mod_12.obj $(OUT)/net_mod_13.obj $(OUT)/net_mod_14.obj $(OUT)/net_mod_15.obj

all: $(OUT)/app.bin

$(OUT):
	mkdir -p $(OUT)

$(OUT)/core_mod_%.obj: core/mod_%.src runtime.h | $(OUT)
	sed 's/syscall_entry_/obj_entry_/' $< > $@

$(OUT)/fs_mod_%.obj: fs/mod_%.src runtime.h | $(OUT)
	sed 's/syscall_entry_/obj_entry_/' $< > $@

$(OUT)/net_mod_%.obj: net/mod_%.src runtime.h | $(OUT)
	sed 's/syscall_entry_/obj_entry_/' $< > $@

$(OUT)/app.bin: $(OBJS)
	cat $(OBJS) > $@

clean:
	rm -rf $(OUT)

.PHONY: all clean

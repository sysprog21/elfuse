# Frama-C WP proofs

.PHONY: verify check-contracts verify-mutants check-char-signedness \
        check-stub-constants check-stub-shadow print-verify-targets

# Frama-C proof of the ELF parsing core. ELF headers come from untrusted
# binaries, so every offset and extent computed from them is discharged as a
# machine-checked proof rather than reviewed by eye. -wp-rte adds the implicit
# runtime-error goals (overflow, out-of-bounds, invalid dereference) that the
# ACSL contracts alone would not cover.
#
# Model: caveat. The default typed model cannot follow the byte-addressed
# program header buffer, whose entry stride (e_phentsize) is attacker chosen
# and need not match the struct alignment. caveat assumes formal pointer
# parameters do not alias, which the contracts state explicitly via \separated.
# The callers are not in -wp-fct, so nothing checks that they honor it: today
# they pass a malloc'd ph_buf plus distinct stack locals, but a future
# elf_segment_extent(..., &x, &x) would invalidate the proof with no diagnostic.
#
# That caveat is general, and it bites hardest for proved/gva.h: guest.c cannot be
# given to Frama-C at all, so nothing here checks that its call sites honor the
# nine "requires" clauses there. check-acsl-coverage.py closes the other
# direction (a contract assumed because its function was left out of -wp-fct);
# it says nothing about preconditions at call sites.
#
# "make check-contracts" narrows that gap from the runtime side: it rebuilds
# with -DELFUSE_CONTRACT_ASSERT so the five expressible clauses are checked on
# every call the suite makes. The four pointer clauses (\valid x3, \separated)
# have no C expression and stay review-only. The checks call the *_args_ok
# predicates in proved/gva.h, whose <==> contracts are proved here, so a check
# that drifted weaker than the clause it mirrors fails verify-gva.
#
# Install: opam install frama-c, then why3 config detect (without the latter WP
# aborts with "Prover not found" instead of reporting unproved goals).
#
# Data model: Frama-C's -machdep names a C DATA MODEL (type widths, alignment,
# endianness, char signedness), not a code generation target. Nothing here is
# proved "for x86_64" and no x86_64 code is involved; the flag only tells the
# prover how wide a size_t is.
#
# gcc_x86_64 matches arm64 macOS, the platform this host code is compiled for,
# on every property these proofs rest on:
#
#   property               arm64 macOS   gcc_x86_64   used by the proof?
#   pointer / long / size_t  64-bit        64-bit       yes
#   byte order               little        little       yes
#   uint64_t alignment       8             8            yes
#   plain char signedness    signed        signed       see below
#
# The signedness row is the one worth checking rather than recalling, because
# the two arm64 targets in this tree disagree: plain char is SIGNED on Apple's
# arm64, which compiles every proved source, and UNSIGNED on aarch64-linux,
# which the cross toolchain compiles the guest tests with. Both answers come
# from asking those compilers.
#
# Frama-C 33 ships a macos_arm machdep, which sounds like the honest name for
# what is being assumed here, and it is not usable: it is not GCC-based, and
# -include prelude.h pulls in Frama-C's own __fc_gcc_builtins.h, which
# refuses __int128 outside a GCC-based machdep. Measured, not assumed: every
# target aborts at parse time with "use a GCC-based machdep to enable it".
# Revisit if the prelude ever stops being needed.
#
# The RSP proof DOES cover functions taking plain char: gdb_hex_pair,
# gdb_hex_decode, gdb_parse_hex and rsp_checksum. What keeps their results
# signedness-independent is not their parameter types but that every use of a
# char value goes through an explicit (unsigned char) or (uint8_t) cast before
# it is compared or accumulated. That is the invariant to preserve, and it is
# what makes the data model's answer to this question stop mattering: no proved
# function may read a plain char without such a cast.
#
# check-acsl-coverage.py enforces the part a regex can, and its
# CHAR_PARAM_ALLOWLIST carries the rest of the reasoning: a proved function
# that takes a plain char at all must be listed there, so a new one cannot be
# added silently.
FRAMAC ?= frama-c
FRAMAC_DATA_MODEL ?= gcc_x86_64
FRAMAC_TIMEOUT ?= 30

# Provers, tried in order until one discharges the goal. Both are listed
# because each closes goals the other does not, so dropping either loses
# proofs. A run that only has to establish that some goal FAILS does not need
# the second opinion, and pays the full timeout twice per unprovable goal
# without it. Nothing in the tree narrows it: the mutation gate was tried on
# one prover and is unsound that way, because its baseline only shows the
# ORIGINAL goals discharge with the kept prover.
FRAMAC_PROVERS ?= alt-ergo,z3

# The analyzer parses against Frama-C's own modeled libc headers, never the
# host's. -print-share-path runs at recipe time rather than through $(shell) so
# a make invocation with no frama-c installed does not pay for it.

# Per-target preprocessor defines, empty for every target that does not set one.
CPP_DEFS :=

# Two additions, both of which decide whether a .c file can be proved at all.
#
# frama-c-stubs supplies Hypervisor/Hypervisor.h. Frama-C has no Apple SDK, so
# every source reaching src/core/guest.h or src/runtime/thread.h aborted on the
# missing header before parsing began. See the stub for what it declares.
#
# -include prelude.h covers the two things the analyzer needs and a compiler
# provides for free. It pulls in __fc_gcc_builtins.h, where Frama-C models
# __builtin_ctzll, __builtin_add_overflow and the fences; nothing in the modeled
# libc includes that header, so without it those are implicit declarations whose
# argument types are inferred per translation unit, which parses one file at a
# time and then refuses the moment two files disagree on a width. It also pulls
# in stdatomic.h, both for the _Atomic qualifier the front end cannot parse and
# for the atomic_*_explicit vocabulary the tree calls, all of which Frama-C
# models there. That header is where Frama-C states "_Atomic is currently
# ignored", so the concession is the analyzer's own rather than one invented
# here. The qualifier reaches a source through headers it includes first, so the
# definition has to arrive ahead of everything.
#
# Ignoring _Atomic is sound for exactly the reasoning these targets do, which is
# per-function runtime-error and bounds obligations under WP, one thread at a
# time. It would NOT be sound for a concurrency analysis. No target here is one.
#
# Together these are what makes most of the parsing set parse at all: without
# the stubs only a couple of sources load. The rest stop on macOS headers
# Frama-C's libc does not model (sys/mount.h, sys/event.h, sys/sysctl.h,
# sys/xattr.h, sys/attr.h, sys/spawn.h), which is a real modeling gap rather
# than a missing declaration. How many sit on each side moves with the tree, so
# count it rather than quote it: run FRAMAC with FRAMAC_CPP_ARGS over each of
# git ls-files 'src/*.c' and tally the exits.
FRAMAC_STUB_DIR := frama-c-stubs

FRAMAC_CPP_ARGS = -nostdinc \
    -isystem $$($(FRAMAC) -print-share-path)/libc \
    -I$(FRAMAC_STUB_DIR) -include prelude.h -include macos-libc.h -Isrc -I$(BUILD_DIR) \
    $(CPP_DEFS)

# One proof per attacker-facing parser. Each is declared by a single
# verify_target call below; the recipe itself lives in one place.
#
# MIN_GOALS is a floor on obligations GENERATED. "N of N discharged" is not
# evidence on its own: an emptied function body or a dropped contract proves
# 0 of 0. Raise it when adding proved functions; it is a tripwire, not a target.

# Contracts in the shared src/utils.h. Every proof whose source includes that
# header must prove them too, not merely assume them, so this list is appended
# to each such proof's -wp-fct. Proving hex_nibble twice costs a second or two;
# assuming it once is how the RSP proof came to rest on an unchecked axiom.
VERIFY_UTILS_FCTS := hex_nibble

VERIFY_ELF_SRC   := src/core/elf.c
VERIFY_ELF_FCTS  := elf_add_no_wrap elf_phdr_gpa_in_segment \
                    elf_phdr_table_bytes elf_phdr_fetch elf_segment_extent \
                    elf_place_segment elf_check_placement elf_record_load \
                    elf_read_interp \
                    $(VERIFY_UTILS_FCTS)
VERIFY_ELF_MIN_GOALS ?= 156
VERIFY_ELF_MODEL := caveat

# Includes utils.h and elf.h: elf.c includes both, and utils.h already carries
# contracts, so scanning only the .c would let one added there become an
# unchecked axiom for this proof.
VERIFY_ELF_SCAN  := src/core/elf.c src/core/elf.h src/utils.h
VERIFY_ELF_CLAIM := for ANY byte sequence an untrusted ELF can supply
VERIFY_ELF_UNPROVED := the pread/malloc I/O around them stays test-covered

# Proved with the call-site checks compiled IN. Without this the prover never
# sees the GVA_CONTRACT_ASSERT calls, and a check wired to the wrong predicate
# or handed permuted arguments would show up only as a spurious runtime abort
# under check-contracts. With it, WP must discharge each assert from the very
# requires clause it mirrors, so the wiring is machine-checked too.
#
# The only target that needs a preprocessor define, which is why the rule
# template below emits CPP_DEFS for every target and empty for the rest.
VERIFY_GVA_CPP_DEFS := -DELFUSE_CONTRACT_ASSERT
VERIFY_GVA_SRC   := src/proved/gva.h
VERIFY_GVA_FCTS  := gva_pt_table_offset gva_leaf_target gva_chunk_clamp \
                    gva_span_ok gva_leaf_target_args_ok \
                    gva_chunk_clamp_args_ok
VERIFY_GVA_MIN_GOALS ?= 69
VERIFY_GVA_MODEL := typed
VERIFY_GVA_SCAN  := src/proved/gva.h
VERIFY_GVA_CLAIM := for ANY guest address, length, and page-table content
VERIFY_GVA_UNPROVED := the walk and copy loops around them stay test-covered

VERIFY_RSP_SRC   := src/debug/gdbstub-rsp.c
VERIFY_RSP_FCTS  := $(VERIFY_UTILS_FCTS) gdb_hex_pair gdb_hex_decode \
                    gdb_parse_hex rsp_checksum
VERIFY_RSP_MIN_GOALS ?= 98

# typed, not caveat: gdb_hex_decode assigns a pointer RANGE (dst[0 .. len-1]),
# which caveat's flat single-region memory cannot express ("Undefined
# array-size"). elf.c can use caveat because its proved functions assign only
# single locations. Nothing here reinterprets bytes at an attacker-chosen
# stride, which is the reason elf.c needed caveat in the first place.
VERIFY_RSP_MODEL := typed

# Includes utils.h: hex_nibble lives there and the whole RSP proof rests on it.
VERIFY_RSP_SCAN  := src/debug/gdbstub-rsp.c src/utils.h
VERIFY_RSP_CLAIM := for ANY packet bytes a GDB remote can send
VERIFY_RSP_UNPROVED := the socket I/O and framing loop stay test-covered

VERIFY_CMSG_SRC  := src/proved/cmsg.h
VERIFY_CMSG_FCTS := cmsg_entry_bounds
VERIFY_CMSG_MIN_GOALS ?= 19
VERIFY_CMSG_MODEL := typed
VERIFY_CMSG_SCAN := src/proved/cmsg.h
VERIFY_CMSG_CLAIM := for ANY control-message bytes a guest can supply
VERIFY_CMSG_UNPROVED := the walk loop and the host cmsg build stay test-covered

VERIFY_FUSE_SRC  := src/proved/fuse.h
VERIFY_FUSE_FCTS := fuse_frame_count_ok fuse_reply_extent \
                    fuse_clamp_negotiated_write
VERIFY_FUSE_MIN_GOALS ?= 28
VERIFY_FUSE_MODEL := typed
VERIFY_FUSE_SCAN := src/proved/fuse.h
VERIFY_FUSE_CLAIM := for ANY reply frame a guest FUSE daemon can write
VERIFY_FUSE_UNPROVED := the per-opcode payload extents stay test-covered

VERIFY_STACK_SRC  := src/proved/stack.h
VERIFY_STACK_FCTS := stack_take stack_align_down stack_pushed_words \
                    stack_final_sp
VERIFY_STACK_MIN_GOALS ?= 36
VERIFY_STACK_MODEL := typed
VERIFY_STACK_SCAN := src/proved/stack.h
VERIFY_STACK_CLAIM := for ANY argv, envp, and auxv set a guest can present
VERIFY_STACK_UNPROVED := the string writes and push loop stay test-covered

VERIFY_SOCKADDR_SRC  := src/proved/sockaddr.h
VERIFY_SOCKADDR_FCTS := sockaddr_len_ok sockaddr_payload_len
VERIFY_SOCKADDR_MIN_GOALS ?= 11
VERIFY_SOCKADDR_MODEL := typed
VERIFY_SOCKADDR_SCAN := src/proved/sockaddr.h
VERIFY_SOCKADDR_CLAIM := for ANY address length a guest or host can present
VERIFY_SOCKADDR_UNPROVED := the family translation and memcpy stay test-covered

VERIFY_NETLINK_SRC  := src/proved/netlink.h
VERIFY_NETLINK_FCTS := netlink_align_up netlink_rta_bounds netlink_msg_span \
                       netlink_attr_extent
VERIFY_NETLINK_MIN_GOALS ?= 65
VERIFY_NETLINK_MODEL := typed
VERIFY_NETLINK_SCAN := src/proved/netlink.h
VERIFY_NETLINK_CLAIM := for ANY netlink message bytes a guest can send
VERIFY_NETLINK_UNPROVED := the attribute copies stay test-covered

# The two walk loops in netlink.c itself, which verify-netlink above could only
# describe as "test-covered". This is the first target whose source is a .c file
# that needed the Hypervisor stub and -D_Atomic= to parse at all; see
# FRAMAC_CPP_ARGS. The proved helpers are re-proved here rather than assumed,
# for the same reason VERIFY_UTILS_FCTS exists.
VERIFY_NETLINKWALK_SRC  := src/syscall/netlink.c
VERIFY_NETLINKWALK_FCTS := nl_parse_link_filter nl_complete_span nl_put_attr \
                           netlink_align_up netlink_rta_bounds \
                           netlink_msg_span netlink_attr_extent
VERIFY_NETLINKWALK_MIN_GOALS ?= 190

# Bytes, and neither of the two models already in this file. Both walks memcpy a
# wire header out of a uint8_t buffer at an offset the message itself chose, so
# typed leaves every memcpy validity and separation goal open (58 of 74), and
# caveat cannot size the byte array at all ("Undefined array-size"). Typed+cast
# gets 73 of 74. Bytes models memory as bytes, which is what the code does, and
# closes all of them.
VERIFY_NETLINKWALK_MODEL := Bytes
VERIFY_NETLINKWALK_SCAN := src/syscall/netlink.c src/proved/netlink.h
VERIFY_NETLINKWALK_CLAIM := for ANY rtattr chain a guest can write and ANY \
reply buffer state
VERIFY_NETLINKWALK_UNPROVED := the reply builders, the socket I/O, and whether \
their callers honor these preconditions stay test-covered

# The deadline arithmetic in futex.c is proved in place because
# futex_remaining_ns reads the clock. Typed suffices; no function in the set
# touches a byte buffer.
#
# The four proved/timespec.h helpers are re-proved here rather than assumed, the
# same reason VERIFY_UTILS_FCTS exists: futex_remaining_ns rests on
# timespec_to_ns_sat's saturation. All four, not just the two futex.c reaches:
# check-acsl-coverage.py reads the whole of each scanned file, so a contracted
# function left out of the set is an assumed axiom whether or not this target
# calls it, and dropping timespec_to_poll_ms fails the gate by name.
#
# The cost is that verify-mutants lists those four as unmutated under this
# target as well as under verify-timespec, where they are mutated. That is a
# second target proving the same functions, not lost coverage.
VERIFY_FUTEXDEADLINE_SRC  := src/runtime/futex.c
VERIFY_FUTEXDEADLINE_FCTS := futex_remaining_ns futex_quantum_deadline \
                             linux_timespec_is_valid futex_uaddr_is_aligned \
                             timespec_valid timespec_valid_capped \
                             timespec_to_ns_sat timespec_to_poll_ms
VERIFY_FUTEXDEADLINE_MIN_GOALS ?= 128
VERIFY_FUTEXDEADLINE_MODEL := typed
VERIFY_FUTEXDEADLINE_SCAN := src/runtime/futex.c src/proved/timespec.h
VERIFY_FUTEXDEADLINE_CLAIM := for ANY guest deadline and ANY cap the wait \
paths hand it
VERIFY_FUTEXDEADLINE_UNPROVED := futex_make_deadline, which reads the guest \
timespec through guest_read_small and so has no body the analyzer can follow, \
the wait loops that consume the deadline, and whether their callers honor \
these preconditions stay test-covered

VERIFY_SIGFRAME_SRC  := src/proved/sigframe.h
VERIFY_SIGFRAME_FCTS := sigframe_base sigframe_fpsimd_vreg_offset
VERIFY_SIGFRAME_MIN_GOALS ?= 20
VERIFY_SIGFRAME_MODEL := typed
VERIFY_SIGFRAME_SCAN := src/proved/sigframe.h
VERIFY_SIGFRAME_CLAIM := for ANY interrupted stack pointer and frame size, \
and ANY vector register index
VERIFY_SIGFRAME_UNPROVED := the 32-store FPSIMD loop that consumes the offset \
stays test-covered, and so do the magic and size values

# A whole-function proof of build_sigcontext_reserved in src/syscall/signal.c
# was tried and is not here. It reaches 67 of 71 with the Bytes model, and the
# four that stay open are Z3 timeouts on the store loop's frame condition, not
# counterexamples: they survive a 180-second per-goal timeout and a frame
# narrowed from the whole 4096-byte reserved area to the 552 bytes the chain
# writes. Splitting the offset arithmetic into sigframe_fpsimd_vreg_offset above
# is what that attempt bought, and the loop that consumes it stays test-covered.
# The ACSL on the function itself is left in place: it is correct, it states the
# frame, and it is what a stronger model would need to start from.
#
# What the attempt did settle is that signal.c parses at all, which it did not
# before: its one _Atomic(T *) is now spelled as the qualifier form, and the two
# Darwin headers it reaches for have stubs (frama-c-stubs/mach, frama-c-stubs/
# sys/ucontext.h). That is a prerequisite for any later proof in this file.

VERIFY_DIRENT_SRC  := src/proved/dirent.h
VERIFY_DIRENT_FCTS := dirent_reclen dirent_record_bounds
VERIFY_DIRENT_MIN_GOALS ?= 30
VERIFY_DIRENT_MODEL := typed
VERIFY_DIRENT_SCAN := src/proved/dirent.h
VERIFY_DIRENT_CLAIM := for ANY name length a host or FUSE directory can present
VERIFY_DIRENT_UNPROVED := the readdir walk and the name translation stay test-covered

VERIFY_IOV_SRC  := src/proved/iov.h
VERIFY_IOV_FCTS := iov_count_ok iov_total_add iov_advance_index
VERIFY_IOV_MIN_GOALS ?= 40
VERIFY_IOV_MODEL := typed
VERIFY_IOV_SCAN := src/proved/iov.h
VERIFY_IOV_CLAIM := for ANY iovec array a guest can write
VERIFY_IOV_UNPROVED := the per-entry guest_ptr bounds stay test-covered

VERIFY_ASYNCUDATA_SRC  := src/proved/asyncudata.h
VERIFY_ASYNCUDATA_FCTS := async_udata_fd async_udata_gen async_udata_pack
VERIFY_ASYNCUDATA_MIN_GOALS ?= 15
VERIFY_ASYNCUDATA_MODEL := typed
VERIFY_ASYNCUDATA_SCAN := src/proved/asyncudata.h
VERIFY_ASYNCUDATA_CLAIM := for ANY guest fd and slot generation the watcher can arm
VERIFY_ASYNCUDATA_UNPROVED := the kevent registration and the delivery-side owner checks stay test-covered

VERIFY_FDSET_SRC  := src/proved/fdset.h
VERIFY_FDSET_FCTS := fdset_words fdset_fd_index fdset_slot
VERIFY_FDSET_MIN_GOALS ?= 43
VERIFY_FDSET_MODEL := typed
VERIFY_FDSET_SCAN := src/proved/fdset.h
VERIFY_FDSET_CLAIM := for ANY nfds, fd_set bit, or fd-table slot index
VERIFY_FDSET_UNPROVED := the poll translation and the result writeback stay test-covered

VERIFY_TIMESPEC_SRC  := src/proved/timespec.h
VERIFY_TIMESPEC_FCTS := timespec_valid timespec_valid_capped timespec_to_ns_sat timespec_to_poll_ms
VERIFY_TIMESPEC_MIN_GOALS ?= 45
VERIFY_TIMESPEC_MODEL := typed
VERIFY_TIMESPEC_SCAN := src/proved/timespec.h
VERIFY_TIMESPEC_CLAIM := for ANY timespec a guest can write
VERIFY_TIMESPEC_UNPROVED := the deadline bookkeeping around them stays test-covered

VERIFY_SLICE_SRC  := src/proved/slice.h
VERIFY_SLICE_FCTS := slice_clamp
VERIFY_SLICE_MIN_GOALS ?= 17
VERIFY_SLICE_MODEL := typed
VERIFY_SLICE_SCAN := src/proved/slice.h
VERIFY_SLICE_CLAIM := for ANY offset and count a guest can pass to a synthesized read
VERIFY_SLICE_UNPROVED := the buffer synthesis itself stays test-covered

VERIFY_ALIGN_SRC  := src/proved/align.h
VERIFY_ALIGN_FCTS := align_up_ok window_fits
VERIFY_ALIGN_MIN_GOALS ?= 24
VERIFY_ALIGN_MODEL := typed
VERIFY_ALIGN_SCAN := src/proved/align.h
VERIFY_ALIGN_CLAIM := for ANY address, alignment, and search window
VERIFY_ALIGN_UNPROVED := the region-array walk around them stays test-covered

VERIFY_FUTEXHASH_SRC  := src/proved/futexhash.h
VERIFY_FUTEXHASH_FCTS := futex_bucket_index
VERIFY_FUTEXHASH_MIN_GOALS ?= 3
# typed: the arithmetic takes scalars only, no buffer and no aliasing question,
# so nothing here needs a model that assumes separation it cannot check.
VERIFY_FUTEXHASH_MODEL := typed
VERIFY_FUTEXHASH_SCAN := src/proved/futexhash.h
VERIFY_FUTEXHASH_CLAIM := for ANY guest futex address and ANY table size
VERIFY_FUTEXHASH_UNPROVED := the queue walks around it stay test-covered

VERIFY_FUTEXOP_SRC  := src/proved/futexop.h
VERIFY_FUTEXOP_FCTS := futex_op_sign_extend12 futex_op_shift_arg_mask
VERIFY_FUTEXOP_MIN_GOALS ?= 6
# typed: scalar arithmetic on one guest-supplied word, no buffer and no
# aliasing question.
VERIFY_FUTEXOP_MODEL := typed
VERIFY_FUTEXOP_SCAN := src/proved/futexop.h
VERIFY_FUTEXOP_CLAIM := for ANY guest-supplied val3 word
VERIFY_FUTEXOP_UNPROVED := the wake and requeue walks around them stay test-covered
# Includes align.h: request_fits calls align_up_ok and window_fits, so this
# proof must discharge their contracts too, not merely assume them, the same
# reason VERIFY_ELF appends VERIFY_UTILS_FCTS.
#
# MIN_GOALS is the complete count from a real run. Keep the floor at that count
# so a future edit that quietly drops a contract or a runtime-error obligation
# cannot turn a smaller proof into a pass.
#
# mmap_fastpath_pow2_clamped was originally the classic bit-smear
# round-up-to-power-of-two; that form's bound and power-of-two properties
# were confirmed unreachable by these provers (a single OR step already
# times out), the same wall align_up_ok's own history describes one level
# down. Rewritten to a doubling loop with an axiomatized power-of-two ghost
# invariant -- same inputs, same outputs, linear arithmetic instead of
# bitwise -- and it discharges completely; see the comment above it.
VERIFY_MMAPFASTPATH_SRC  := src/proved/mmap-fastpath.h
VERIFY_MMAPFASTPATH_FCTS := mmap_fastpath_request_fits mmap_fastpath_pow2_clamped \
                            mmap_fastpath_window_max mmap_fastpath_arena_size \
                            align_up_ok window_fits
VERIFY_MMAPFASTPATH_MIN_GOALS ?= 93
VERIFY_MMAPFASTPATH_MODEL := typed
VERIFY_MMAPFASTPATH_SCAN := src/proved/mmap-fastpath.h src/proved/align.h
VERIFY_MMAPFASTPATH_CLAIM := for ANY cursor/limit/len and ANY registration history
VERIFY_MMAPFASTPATH_UNPROVED := mmap_fastpath_window_max reporting an actual array member \
                                 rather than just an upper bound (the loop-invariant \
                                 preservation step for that claim times out even with a \
                                 ghost witness index, confirmed unreachable, see the comment \
                                 above it); the atomic control-block bookkeeping around all \
                                 four stays test-covered

VERIFY_PATHDEPTH_SRC  := src/proved/pathdepth.h
VERIFY_PATHDEPTH_FCTS := path_depth_push path_depth_pop
VERIFY_PATHDEPTH_MIN_GOALS ?= 24
VERIFY_PATHDEPTH_MODEL := typed
VERIFY_PATHDEPTH_SCAN := src/proved/pathdepth.h
VERIFY_PATHDEPTH_CLAIM := for ANY component depth a guest path can reach
VERIFY_PATHDEPTH_UNPROVED := the component scan and the mark writes stay test-covered

# -wp-fct wants one comma-separated argument; the lists stay space-separated so
# the recipe can iterate them for the banner.
verify_empty :=
verify_space := $(verify_empty) $(verify_empty)
verify_comma := ,
commafy = $(subst $(verify_space),$(verify_comma),$(strip $(1)))

# Per-proof values, consumed by the single recipe below through target-specific
# variables. Adding a proof means adding a VERIFY_<NAME>_* block, one line of
# assignments here, and the target name to the shared rule; the recipe itself is
# written once.

# GNU make has no lowercase function, and the variable names are upper while
# the target names are lower. One $(subst) chain per letter actually used by a
# target name is enough and stays readable; a new target using a letter not
# listed here shows up immediately as a literal upper-case character in the
# rule name rather than silently misbehaving.
# Lowercase a target name. Spelled out per letter because make has no case
# function; J, Y and Z were missing from this chain, so a proof target whose
# name contained one produced a rule nobody could invoke -- silently, since the
# .PHONY list and the rule name were wrong in the same way. Keep all 26.
lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$(1)))))))))))))))))))))))))))

# The proof targets, derived rather than listed. Make knows every variable it
# has read, so the set of VERIFY_<T>_SRC assignments above IS the target list;
# writing it out again is how the four copies of it (this file twice, the CI
# matrix, and src/proved/) drifted apart in the first place.
VERIFY_TARGETS := $(sort $(patsubst VERIFY_%_SRC,%,$(filter VERIFY_%_SRC,$(.VARIABLES))))
VERIFY_TARGET_NAMES := $(call lc,$(VERIFY_TARGETS))
VERIFY_RULES := $(addprefix verify-,$(VERIFY_TARGET_NAMES))

# Declared here, not in the .PHONY at the top of the file: VERIFY_RULES does
# not exist yet at that point and would expand to nothing.
.PHONY: $(VERIFY_RULES)

## Print the proof target names, one per line (CI reads this to build its matrix)
print-verify-targets:
	@printf '%s\n' $(VERIFY_TARGET_NAMES)

# One rule template, instantiated per target. The target-specific variables
# below are exactly what the shared recipe consumes; NAME and TARGET differ only
# because a mutation run overrides NAME to keep concurrent logs apart.
define verify-target-vars
verify-$(call lc,$(1)): NAME := $(call lc,$(1))
verify-$(call lc,$(1)): TARGET := $(call lc,$(1))
verify-$(call lc,$(1)): SRC := $$(VERIFY_$(1)_SRC)
verify-$(call lc,$(1)): FCTS := $$(VERIFY_$(1)_FCTS)
verify-$(call lc,$(1)): FCT_ARG := $$(call commafy,$$(VERIFY_$(1)_FCTS))
verify-$(call lc,$(1)): MIN_GOALS := $$(VERIFY_$(1)_MIN_GOALS)
verify-$(call lc,$(1)): MODEL := $$(VERIFY_$(1)_MODEL)
verify-$(call lc,$(1)): SCAN := $$(VERIFY_$(1)_SCAN)
verify-$(call lc,$(1)): CLAIM := $$(VERIFY_$(1)_CLAIM)
verify-$(call lc,$(1)): UNPROVED := $$(VERIFY_$(1)_UNPROVED)
verify-$(call lc,$(1)): CPP_DEFS := $$(VERIFY_$(1)_CPP_DEFS)
endef

$(foreach t,$(VERIFY_TARGETS),$(eval $(call verify-target-vars,$(t))))

# NAME and TARGET look redundant and are not. NAME picks the log path and is
# overridden per mutation run so concurrent runs do not share a file; TARGET is
# the target's identity and must stay put, or a mutation run would ask the
# signedness check about a target that does not exist.
#
# One recipe, shared by every verify-* target above. Listing several targets on
# one rule gives each of them this recipe; the target-specific variables select
# what gets proved.
#
# The recipe only runs the prover. Deciding whether the run counts as a proof
# lives in scripts/check-wp-result.py: as a shell recipe it needed every $
# doubled and every line continued, which put the gate that matters out of
# reach of any test.
$(VERIFY_RULES): check-stub-constants check-stub-shadow | $(BUILD_DIR)
	@command -v $(FRAMAC) >/dev/null 2>&1 || { \
		printf "$(RED)frama-c not found$(RESET) "; \
		printf "(set FRAMAC=, or eval \$$(opam env --switch=<switch>))\n"; \
		exit 1; \
	}
	@python3 scripts/check-acsl-coverage.py --target verify-$(NAME) \
	    --fcts "$(FCTS)" $(SCAN)
	@python3 scripts/check-char-signedness.py --cc '$(CC)' --target $(TARGET)
	@echo "  PROVE   $(SRC) (Frama-C WP: weakest-precondition prover)"
	@echo "          claim: $(CLAIM),"
	@echo "                 these compute no out-of-bounds access and no overflow"
	@for f in $(FCTS); do echo "                 - $$f"; done
	@echo "          memory model: $(MODEL);  data model: $(FRAMAC_DATA_MODEL)"
	@echo "          (data model is type widths only, and matches arm64"
	@echo "           macOS on width, order, alignment and char signedness)"
	@$(FRAMAC) -machdep $(FRAMAC_DATA_MODEL) \
	    -cpp-extra-args="$(FRAMAC_CPP_ARGS)" \
	    $(SRC) -wp -wp-rte -wp-model $(MODEL) \
	    -wp-fct $(FCT_ARG) \
	    -wp-prover $(FRAMAC_PROVERS) -wp-timeout $(FRAMAC_TIMEOUT) \
	    > $(BUILD_DIR)/verify-$(NAME).log 2>&1; \
	python3 scripts/check-wp-result.py --status $$? \
	    --log $(BUILD_DIR)/verify-$(NAME).log --min-goals $(MIN_GOALS) \
	    --src $(SRC) --unproved "$(UNPROVED)"

## Assert every proof target rejects a known-broken source
#
# Complements the other two gates rather than duplicating them: MIN_GOALS
# catches a gutted body, check-acsl-coverage.py catches a contracted function
# left out of the proof set, and this catches a contract whose clauses do not
# actually bite. Mutations run against copies under $(BUILD_DIR)/mutants, so a
# run never edits the tree.
# MUTANT_JOBS overrides the script's one-per-core default, which a CI runner
# with few cores would otherwise resolve to near-serial.
# MUTANT_SINCE restricts the run to targets whose source differs from that ref,
# for a local run that only wants what a branch touched. Leave it empty to run
# the whole set, which is what the base branch needs to do. This asks
# scripts/proof-scope.py the same question CI's mutation matrix asks, so a
# local run reproduces that scope; CI does not pass MUTANT_SINCE, since a leg
# that exists at all has a target the diff reaches and applying the scoping a
# second time inside the leg selects everything.
# MUTANT_TARGET restricts the run to one proof target, letting CI shard the
# full set across parallel jobs instead of one job working through all of it.
# Leave it empty to run every target in one process, which is what a local
# "make verify-mutants" wants.
MUTANT_JOBS ?=
MUTANT_SINCE ?=
MUTANT_TARGET ?=
verify-mutants:
	@echo "  MUTANT  proof targets against known-broken sources"
	$(Q)python3 scripts/check-mutants.py --cc '$(CC)' \
	    $(if $(MUTANT_JOBS),--jobs $(MUTANT_JOBS),) \
	    $(if $(MUTANT_SINCE),--changed-since $(MUTANT_SINCE),) \
	    $(if $(MUTANT_TARGET),--target $(MUTANT_TARGET),)

## Show that no proved function depends on plain-char signedness
#
# Every verify-* target already runs this for itself, so "make verify" gets it
# without listing it; this entry point is for checking the whole set at once.
#
# The data-model note above says the tree's real arm64 compilers disagree on
# plain-char signedness, and the proofs stay portable because no proved
# function reads a plain char without an explicit cast. check-acsl-coverage.py
# checks that with a regex, which cannot see a char behind a typedef or a macro.
# This asks the compiler instead, per proved function and at -O0: identical
# code under -fsigned-char and -funsigned-char means that function behaves the
# same either way, which is the invariant rather than a proxy for it.
check-char-signedness:
	@echo "  CHARSIGN proof sources under both char signedness settings"
	$(Q)python3 scripts/check-char-signedness.py --cc '$(CC)'

# Proof jobs. Each verify-* target is one frama-c process writing its own log
# and sharing nothing with the others, so the only thing serializing them was
# make itself.
VERIFY_JOBS ?= $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

## Run every Frama-C proof
#
# Recursive rather than a prerequisite list, so a plain "make verify" gets the
# parallelism instead of only the invocations that remember -j. The leading '+'
# is what keeps this expanding under -n: make looks for a literal $(MAKE) in the
# unexpanded recipe line to decide that, and marks the line as still-runs.
#
# The -j is added only when the caller did not bring one. A forced -j in a
# submake makes it drop the inherited jobserver and start that many processes
# regardless of the outer limit, so "make -j2 verify" would run VERIFY_JOBS of
# them. Passing nothing lets the jobserver do its job.
#
# "make -j1 verify" is serial under GNU make 4.x, which keeps -j1 in MAKEFLAGS
# for the filter below to find. Apple's /usr/bin/make is 3.81 and records
# nothing for -j1, so there it reads as a plain invocation and parallelizes;
# VERIFY_JOBS=1 asks for serial in a way both understand.
## Assert every frama-c-stubs constant matches the macOS SDK
#
# The stub headers claim to carry Darwin's real values, and the analyzer never
# links, so a wrong one cannot fail a build: it silently changes what the proofs
# reason about. ETOOMANYREFS was written as 62, which is Darwin's ELOOP and
# another arm of the same linux_errno() switch, and only a review caught it.
check-stub-constants:
	$(Q)python3 scripts/check-stub-constants.py

## Assert a shadow stub's rename still hits exactly one declaration
#
# frama-c-stubs/sys/socket.h and frama-c-stubs/pthread.h take the modeled libc
# header whole and rename one name inside it. That is sound only while the
# modeled header names it once. A second use would follow the rename into a
# prototype and change a signature, and the file would still parse and the
# proofs would still discharge, about a different program.
check-stub-shadow:
	$(Q)python3 scripts/check-stub-shadow.py --self-test
	$(Q)python3 scripts/check-stub-shadow.py $(if $(FRAMAC),--frama-c $(FRAMAC))

verify:
	+@$(MAKE) --no-print-directory \
	    $(if $(filter -j%,$(MAKEFLAGS)),,-j$(VERIFY_JOBS)) $(VERIFY_RULES)

## Rebuild with the proved/gva.h precondition checks live, then run the suite
#
# Separate from "make check" rather than folded into it: gva_leaf_target and
# gva_chunk_clamp sit on the guest_read / guest_write hot path, and the tree has
# no NDEBUG release split that would compile the checks out again.
#
# Builds into its own directory rather than rebuilding in place. Sharing
# $(BUILD_DIR) would leave instrumented objects behind, and a later "make
# elfuse" would silently relink them: a default-looking binary carrying the
# checks on its hot path. A separate tree also means no -B is needed, since it
# starts empty.
check-contracts:
	@echo "  CONTRACT proved/gva.h call-site preconditions (5 of 9 clauses)"
	$(Q)$(MAKE) BUILD_DIR=$(BUILD_DIR)/contracts \
	    EXTRA_CFLAGS="-DELFUSE_CONTRACT_ASSERT $(EXTRA_CFLAGS)" check

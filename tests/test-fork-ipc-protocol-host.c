/*
 * Native-host unit test for fork IPC protocol identity.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The fork child is spawned from elfuse_path, so a long-running parent can
 * handshake with a newer on-disk child after an upgrade. The first header word
 * is therefore the protocol identity, not just a frame delimiter.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "runtime/fork-state.h"

#define LEGACY_ELFK_MAGIC 0x454C464BU
#define PREVIOUS_ELFL_MAGIC 0x454C464CU
#define PREVIOUS_ELFM_MAGIC 0x454C464DU
#define PREVIOUS_ELFN_MAGIC 0x454C464EU
#define PREVIOUS_ELFO_MAGIC 0x454C464FU
#define PREVIOUS_ELFP_MAGIC 0x454C4650U
#define PREVIOUS_ELFQ_MAGIC 0x454C4651U

_Static_assert(FORK_IPC_PROTOCOL_MAGIC == 0x454C4652U,
               "fork IPC protocol magic must remain ELFR until the next "
               "incompatible wire-format change");
_Static_assert(IPC_MAGIC_HEADER == FORK_IPC_PROTOCOL_MAGIC,
               "header magic must be the protocol identity");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != LEGACY_ELFK_MAGIC,
               "current protocol must reject old ELFK children/parents");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != PREVIOUS_ELFL_MAGIC,
               "NOFILE header fields require rejecting ELFL peers");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != PREVIOUS_ELFM_MAGIC,
               "start_stack header field requires rejecting ELFM peers");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != PREVIOUS_ELFN_MAGIC,
               "region fork metadata requires rejecting ELFN peers");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != PREVIOUS_ELFO_MAGIC,
               "per-fd description ownership requires rejecting ELFO peers");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != PREVIOUS_ELFP_MAGIC,
               "the per-fd intercept marker requires rejecting ELFP peers");
_Static_assert(FORK_IPC_PROTOCOL_MAGIC != PREVIOUS_ELFQ_MAGIC,
               "the dirty bitmap wire requires rejecting ELFQ peers");
_Static_assert(IPC_MAGIC_SENTINEL != FORK_IPC_PROTOCOL_MAGIC,
               "process-state sentinel must not alias the header protocol");

_Static_assert(offsetof(ipc_header_t, magic) == 0,
               "protocol magic must be the first header field");
_Static_assert(offsetof(ipc_header_t, ipa_bits) == sizeof(uint32_t),
               "ipa_bits must immediately follow magic; there is no version "
               "slot in the fork IPC header");

/* Enforce the bool typing of has_shm / is_rosetta via _Generic so a silent
 * widening to uint8_t / uint32_t (which would still match sizeof(bool)) fails
 * the build instead of accidentally re-shaping the wire.
 */
_Static_assert(_Generic(((ipc_header_t *) 0)->has_shm, bool: 1, default: 0),
               "has_shm must remain a bool field");
_Static_assert(_Generic(((ipc_header_t *) 0)->is_rosetta, bool: 1, default: 0),
               "is_rosetta must remain a bool field");

/* The wire is private to one build (FORK_IPC_PROTOCOL_MAGIC bumps on every
 * incompatible layout change), but parent and child still need to agree on the
 * width of the bool flags they exchange. Pin the assumption so a future
 * toolchain that widens _Bool fails the build instead of silently desyncing.
 */
_Static_assert(sizeof(bool) == 1,
               "fork IPC bool fields assume a 1-byte _Bool; pin this width "
               "until the wire format uses uint8_t explicitly");

int main(void)
{
    printf("test-fork-ipc-protocol-host: protocol magic 0x%08x\n",
           FORK_IPC_PROTOCOL_MAGIC);
    return 0;
}

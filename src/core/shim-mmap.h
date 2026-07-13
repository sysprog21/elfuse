/*
 * Freestanding EL1 mmap fast path.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The assembly exception shim owns the saved-register frame and calls this
 * module only for mmap.  A true return means X0 in the saved
 * frame contains the completed syscall result; false asks the shim to forward
 * the original frame to HVC #5 unchanged.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define EL1_SAVED_GPRS 31u

bool el1_mmap_fastpath(uint64_t saved_gprs[static EL1_SAVED_GPRS]);

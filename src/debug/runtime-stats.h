/*
 * Runtime stats coordinator.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>

#include "core/guest.h"

void runtime_stats_init(int argc, char **argv);
bool runtime_stats_enabled(void);
void runtime_stats_reset_baseline(void);
void runtime_stats_dump(const guest_t *g, const char *reason, bool final);
void runtime_stats_maybe_dump_signal(const guest_t *g);

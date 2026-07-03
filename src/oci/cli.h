/* `elfuse oci` subcommand dispatch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sits on the side of the main argv parser: when argv[1] == "oci" the rest
 * of the command line is forwarded here. Subcommands are pull, inspect,
 * prune, and list. Only inspect parses a reference today; the others return
 * a deterministic "not yet implemented" exit so users can discover the
 * surface without crashes.
 */

#pragma once

/* argc/argv are the slice starting at "oci" (i.e. argv[0] == "oci"), or the
 * full command line when main() dispatched on a BusyBox-style multicall name
 * (argv[0] == ".../elfuse-container"). Returns a process exit code suitable
 * for main() to return directly.
 */
int oci_cli_main(int argc, char **argv);

/* Name the CLI was invoked as, for usage/help text: "elfuse oci" by default,
 * or the multicall basename (e.g. "elfuse-container") when oci_cli_main was
 * entered through an argv[0] alias. Stable static storage; never NULL.
 */
const char *oci_cli_name(void);

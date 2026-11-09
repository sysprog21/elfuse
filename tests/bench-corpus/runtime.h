/* bench-corpus shared header -- fixed synthetic source (see README.md). */

struct request {
    int opcode;
    unsigned long state;
    unsigned long args[6];
};

struct module_ops {
    const char *name;
    int entry_count;
};

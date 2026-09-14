# Contributing to `elfuse`

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to
[elfuse](https://github.com/sysprog21/elfuse) hosted on GitHub.
These are mostly guidelines, not rules.
Use your best judgment, and feel free to propose changes to this document in a pull request.

## Issues

This project uses GitHub Issues to track ongoing development, discuss project plans, and keep track
of bugs.
Be sure to search for existing issues before you create another one.

Initially, it is advisable to create an issue on GitHub for bug reports, feature requests, or
substantial pull requests, as this offers a platform for discussion with both the community and
project maintainers.

Engaging in a conversation through a GitHub issue before making a contribution is crucial to ensure
the acceptance of your work.
We aim to prevent situations where significant effort is expended on a pull request that might not
align with the project's design principles.
For example, it might turn out that the feature you propose is more suited as an independent module
that complements this project, in which case we would recommend that direction.

For minor corrections, such as typo fixes, small refactoring, or updates to documentation/comments,
filing an issue is not typically necessary.
What constitutes a "minor" fix involves discretion; however, examples include:
* Correcting spelling mistakes
* Minor code refactoring
* Updating or editing documentation and comments

Nevertheless, there may be instances where, upon reviewing your pull requests, we might request an
issue to be filed to facilitate discussion on broader design considerations.

Visit our [Issues page on GitHub](https://github.com/sysprog21/elfuse/issues) to search and submit.

## Ground Rules

Contributions from developers across corporations, academia, and individuals are welcome.
Participation requires adherence to a few ground rules:
* Code follows the C coding style below.
  There is some flexibility in basic style, but stay with the standard already in the file you are
  editing.
  Complex algorithmic constructs without explanatory comments will not be accepted.
* Shell and Python scripts are formatted before submission, with the project's flags rather than
  your own.
  Run `make indent` and the flags are settled for you.
* External pull requests document their intent in the pull request description.
* Documentation, code comments, and other English material use the American English (`en_US`)
  dialect: "initialize" over "initialise", "color" over "colour".

## Formatting and Tooling

Software requirements:
* [clang-format](https://clang.llvm.org/docs/ClangFormat.html) version 22, exactly.
  `.ci/check-format.sh` rejects any other version, because the output of a neighboring release
  differs enough to fail a file that the pinned version considers clean.
* [commentflow](https://github.com/sysprog21/commentflow), which reflows comments to the column
  limit.
  `make indent` requires it and fails with the project URL when it is missing, rather than
  formatting the tree to a standard that depends on who ran it.
* [shellcheck](https://www.shellcheck.net/), at warning severity.
* [shfmt](https://github.com/mvdan/sh) and [black](https://github.com/psf/black), for shell and
  Python.
  Both are opt-in: neither version is pinned and no gate reads their output, so running them
  unconditionally rewrites files nothing asked to change. Set `FORMAT_SHELL=1` or `FORMAT_PY=1`
  to include them, and `make indent` still skips the step when the tool is absent.

To maintain a uniform style across languages, run:
* `make indent` to rewrite in place: `commentflow` over the C, shell, and assembly sources first,
  then clang-format over the C sources. Adding `FORMAT_SHELL=1` runs
  `shfmt -ln=bash -i 4 -ci -bn -fn -sr` over the shell scripts and `FORMAT_PY=1` runs `black` over
  the Python scripts.
  The order is not arbitrary. clang-format breaks a comment line that runs past the limit but never
  refills a short-wrapped one, so commentflow
  runs first and clang-format normalizes whatever indentation the reflow produced; the pair
  converges, and a file that has been through both is clean under both.
* `make check-format` to verify without rewriting: comment reflow, clang-format compliance,
  shellcheck over every script the repository carries, the syscall dispatch table, and the
  test-matrix skip lists.

Prefer these targets over invoking the formatters by hand.
They select their inputs through `git ls-files` with an explicit pathspec, so vendored trees under
`externals/` never reach a formatter.

## Coding Style for Shell Script

Shell scripts must be clean, consistent, and portable.
The following `shfmt` rules (check `.editorconfig` file) are enforced project-wide:
* Use spaces for indentation.
* Indent with 4 spaces.
* Use Unix-style line endings (LF).
* Remove trailing whitespace at the end of lines.
* Ensure the file ends with a newline.
* Place the opening brace of a function on the next line.
* Indent `case` statements within `switch` blocks.
* Add spaces around redirection operators (e.g., `>`, `>>`).
* Place binary operators (e.g., `&&`, `|`) on the next line when breaking lines.

## Coding Style for Python

Python scripts must be clean, consistent, and adhere to modern Python best practices.
The following formatting rules are enforced project-wide using `black`:

* Use 4 spaces for indentation (never tabs).
* Limit lines to 80 characters maximum.
* Use double quotes for strings (unless single quotes avoid escaping).
* Use trailing commas in multi-line constructs.
* Format imports according to PEP 8 guidelines.
* Use Unix-style line endings (LF).
* Remove trailing whitespace at the end of lines.
* Ensure files end with a newline.

## Coding Style for Modern C

This coding style is a variant of the [K&R
style](https://en.wikipedia.org/wiki/Indentation_style#K&R).
Adhere to established practices while being open to innovation.
Maintain consistency, adopt the latest C standards, and embrace modern compilers along with their
advanced static analysis capabilities and sanitizers.

The tree is C11 in practice: `_Thread_local`, `_Atomic`, and `_Static_assert` all appear in `src/`,
and headers use `#pragma once`.
No `-std=` flag is set, so the compiler default applies and GNU extensions are available; use one
only where a platform header or an HVF construct leaves no choice.

The build treats warnings as errors and turns on a set worth knowing before you write the code:
`-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wformat=2
-Wimplicit-fallthrough -Wundef -Wnull-dereference -Wno-unused-parameter`.
The last of those is the one exemption: an unused parameter is expected at a callback signature the
guest ABI fixes, so it does not have to be annotated away.
Two of those make rules in this document compiler-enforced rather than advisory:
`-Wstrict-prototypes` rejects the empty parameter list, and `-Wmissing-prototypes` rejects a
non-static function with no prototype.
`WERROR=0` exists for the case where a newer compiler invents a warning this tree has not seen yet;
it is not a way to land a warning.

One rule outranks every other rule in this document:

> The single most important rule when writing code is this: check the surrounding code and try to
> imitate it.

Whatever the sections below recommend, when you patch existing code, keep the style already in that
file even if it is not your favorite.
A patch written in a style foreign to its surroundings costs the reviewer more than it saved the
author.

Three project-wide rules that no formatter will fix for you:
* Comment prose and commit messages are ASCII only. The one thing that is not prose, a diagram, is
  the one exception, and it is spelled out below.
  No em dashes, no typographic quotes, and no non-ASCII arrows outside a diagram.
  Reword an em dash away with a comma, a colon, parentheses, or two sentences.
  A spaced `--` carries the em dash's register rather than replacing it, and a bare `-` joining two
  clauses does the same, so reach for the rewording first.
  Both stay legal and neither earns a review comment on its own, but prose leaning on them has
  disguised the em dash rather than removed it.
  Drop the markdown as well: inside a comment a symbol or path is written bare, as EPOLL_CTL_MOD or
  tests/foo.c, not wrapped in backticks.
  This governs what goes into a `.c`, `.h`, or `.S` file and into a commit message.
  Markdown documents, this one included, use ordinary markdown.

  The exception, in full: a diagram drawn inside a comment may use the Unicode box-drawing block
  (U+2500 to U+257F), plus the geometric arrowhead that terminates an edge, of which the diagrams in
  this tree use one, U+25BE.
  A flow or a layout a reader has to see is worth more than the byte width of its borders, and those
  glyphs have corners, junctions, and arrowheads that `+`, `-`, and `|` only approximate.
  The exception covers the picture and nothing else.
  The sentence introducing it, and every other comment in the file, stay ASCII, and a commit message
  has no exception at all.
  Draw the whole picture in one charset rather than mixing the two, and keep it inside the column
  limit like any other comment.
* Comments use `/* ... */` exclusively.
  `//` never appears, not even for a single line.
* Filenames use kebab-case (`proc-state.c`), identifiers use snake_case (`proc_state`).
  Keeping the underscore out of filenames avoids a visual collision between a symbol and the file
  that holds it.

### Indentation

In this coding style guide, the use of 4 spaces for indentation instead of tabs is strongly enforced
to ensure consistency.
Always apply a single space before and after comparison and assignment operators to maintain
readable code.
Additionally, it is crucial to include a single space after every comma. e.g.,
```c
for (int i = 0; i < 10; i++) {
    printf("%d\n", i);
    /* some operations */
}
```

The tab character (ASCII 0x9) should never appear within any source code file.
When indentation is needed in the source code, align using spaces instead.
The width of the tab character varies by text editor and programmer preference, making consistent
visual layout a continual challenge during code reviews and maintenance.

### Line length

All lines should typically remain within 80 characters, with longer lines wrapped as needed.
For code that limit is `.clang-format`'s `ColumnLimit`; for comment text it is `commentflow`, which
reads the same key, so there is one number and not two.
This practice is supported by several valid rationales:
* It encourages developers to write concise code.
* Smaller portions of information are easier for humans to process.
* It assists users of vi/vim (and potentially other editors) who use vertical splits.
* It is especially helpful for those who may want to print code on paper.

### Comments

Multi-line comments should have the opening and closing characters on separate lines, with the
content lines prefixed by a space and an asterisk (`*`) for alignment, e.g.,
```c
/*
 * This is a multi-line comment.
 */

/* One line comment. */
```

Use multi-line comments for more elaborate descriptions or before significant logical blocks of
code.

Do not hand-wrap comment text.
`commentflow` reflows it to the column limit it reads out of `.clang-format`, which is the same 80
the section above states, so the width rule has one owner rather than a rule in this document and a
habit in your editor.
Write the sentence and let `make indent` place the breaks.

A labelled pair such as `Usage:` and `Example:` needs a blank comment line between the two blocks, or
the reflow reads them as one paragraph and splices the two commands onto a single line.

What it will not touch, so you can still lay these out by hand: blank lines inside a comment, the
existing indentation, a preformatted region (a table, a diagram, a code fence), an SPDX
identifier, and a tool directive such as `clang-format off`.
A diagram of a race window or a byte layout survives the reflow intact.

Single-line comments should be written in C89 style:
```c
    return (uintptr_t) val;  /* return a bitfield */
```

Leave two spaces between the statement and the inline comment.
Avoid commenting out code directly.
Instead, use `#if 0` ... `#endif` when it is intentional.

All assumptions should be clearly explained in comments.
Use the following markers to highlight issues and make them searchable:
* `WARNING`: Alerts a maintainer to the risk of changing this code. e.g., a delay loop counter's
  terminal value was determined empirically and may need adjustment when the code is ported or the
  optimization level is tweaked.
* `NOTE`: Provides descriptive comments about the "why" of a chunk of code, as opposed to the "how"
  usually included in comments. e.g., a chunk of driver code may deviate from the datasheet due to a
  known erratum in the chip, or an assumption made by the original programmer is explained.
* `TODO`: Indicates an area of the code that is still under construction and explains what remains
  to be done.
  When appropriate, include an all-caps programmer name or set of initials before the word `TODO`.

Keep the documentation as close to the code as possible.

### Spacing and brackets

Ensure that the keywords `if`, `while`, `for`, `switch`, and `return` are always followed by a
single space when there is additional code on the same line.
Follow these spacing guidelines:
* Place one space after the keyword in a conditional or loop.
* Do not use spaces around the parentheses in conditionals or loops.
* Insert one space before the opening curly bracket.

For example:
```c
do {
    /* some operations */
} while (condition);
```

Functions (their declarations or calls), `sizeof` operator or similar macros shall not have a space
after their name/keyword or around the brackets, e.g.,
```c
unsigned total_len = offsetof(obj_t, items[n]);
unsigned obj_len = sizeof(obj_t);
```

Use brackets to avoid ambiguity and with operators such as `sizeof`, but otherwise avoid redundant
or excessive brackets.

Assignment operators (`=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `<<=`, and `>>=`) should
always have a space before and after them.
For example:
```c
count += 1;
```

Binary operators (`+`, `-`, `*`, `/`, `%`, `<`, `<=`, `>`, `>=`, `==`, `!=`, `<<`, `>>`, `&`, `|`,
`^`, `&&`, and `||`) should also be surrounded by spaces.
For example:
```c
current_conf = prev_conf | (1 << START_BIT);
```

Unary operators (`++`, `--`, `!`, and `~`) should be written without spaces between the operator and
the operand.
For example:
```c
bonus++;
if (!play)
    return STATE_QUIET;
```

The ternary operator (`?` and `:`) should have spaces on both sides.
For example:
```c
static uint32_t max(uint32_t a, uint32_t b)
{
    return (a > b) ? a : b;
}
```

Structure pointer (`->`) and member (`.`) operators should not have surrounding spaces.
Similarly, array subscript operators (`[` and `]`) and function call parentheses should be written
without spaces around them.

### Parentheses

Avoid relying on C's operator precedence rules, as they may not be immediately clear to those
maintaining the code.
To ensure clarity, always use parentheses to enforce the correct execution order within a sequence
of operations, or break long statements into multiple lines if necessary.

When using logical AND (`&&`) and logical OR (`||`) operators, each operand should be enclosed in
parentheses, unless it is a single identifier or constant.
For example:
```c
if ((count > 100) && (detected == false)) {
    character = C_ASSASSIN;
}
```

### Variable names and declarations

Ensure that functions, variables, and comments are consistently named using English words.
Global variables should have descriptive names, while local variables can have shorter names.
It is important to strike a balance between being descriptive and concise.
Each variable's name should clearly reflect its purpose.

Use [snake_case](https://en.wikipedia.org/wiki/Snake_case) for naming conventions, and avoid using
"camelCase." Additionally, do not use Hungarian notation or any other unnecessary prefixes or
suffixes.

When declaring pointers, follow these spacing conventions:
```c
const char *name;             /* Pointer to const data */
conf_t *const cfg;            /* Const pointer to mutable data */
const uint8_t *const charmap; /* Const pointer to const data */
const void *restrict key;     /* Restrict pointer to const data; does not alias */
```

The asterisk binds to the name, never to the type, and no space separates it from what follows it.
This is not a preference you can spell the other way: `.clang-format` sets `PointerAlignment:
Right`, so `conf_t * const cfg` is rewritten to `conf_t *const cfg` and the unformatted spelling
fails the check.

Declare a local variable where it is first used rather than at the top of the function (see
[Initialization](#initialization)).
When several variables of the same type are introduced at the same point, declare them on one line:
```c
void func(void)
{
    char a, b;  /* OK: introduced together */

    char a;
    char b;     /* Avoid: same type, same point, split over two lines */
}
```

Do not fold a function call into a declaration that introduces more than one variable.
The reader cannot tell at a glance which variable the call initializes:
```c
int len, ret = compute();  /* Avoid */

int len;
int ret = compute();       /* OK */
```

Do not invent an identifier that begins with `_` or `__`.
Those forms are reserved for the implementation, and a collision with a libc or compiler internal
surfaces as a diagnostic nowhere near the declaration that caused it.
This constrains only the names you define.
Spelling one the toolchain already provides (`__attribute__`, `_Atomic`, `_Static_assert`,
`__atomic_load_n`) is exactly how those features are reached.

Always include a trailing comma in the last element of a structure initialization, including its
nested elements, to help `clang-format` correctly format the structure.
However, this comma can be omitted in very simple and short structures.
```c
typedef struct {
    int width, height;
} screen_t;

screen_t s = {
    .width = 640,
    .height = 480,   /* comma here */
};
```

### Type definitions

Declarations shall be on the same line, e.g.,
```c
typedef void (*dir_iter_t)(void *, const char *, struct dirent *);
```

_Typedef_ structures rather than pointers.
Note that structures can be kept opaque if they are not dereferenced outside the translation unit
where they are defined.
Pointers can be _typedefed_ only if there is a very compelling reason.

New types may be suffixed with `_t`.
Structure name, when used within the translation unit, may be omitted, e.g.:

```c
typedef struct {
    unsigned if_index;
    unsigned addr_len;
    addr_t next_hop;
} route_info_t;
```

### Initialization

Do not initialize static and global variables to `0`; the compiler will do this.
When a variable is declared inside a function, it is not automatically initialized.

```c
static uint8_t a;  /* Global variable 'a' is set to 0 by the compiler */

void foo(void)
{
    /* 'b' is uninitialized and set to whatever happens to be in memory */
    uint8_t b;
    ...
}
```

Embrace C99 structure initialization where reasonable, e.g.,
```c
static const crypto_ops_t openssl_ops = {
    .create = openssl_crypto_create,
    .destroy = openssl_crypto_destroy,
    .encrypt = openssl_crypto_encrypt,
    .decrypt = openssl_crypto_decrypt,
    .hmac = openssl_crypto_hmac,
};
```

Embrace C99 array initialization, especially for the state machines, e.g.,
```c
static const uint8_t tcp_fsm[TCP_NSTATES][2][TCPFC_COUNT] = {
    [TCPS_CLOSED] = {
        [FLOW_FORW] = {
            /* Handshake (1): initial SYN. */
            [TCPFC_SYN] = TCPS_SYN_SENT,
        },
    },
    ...
};
```

An automatic pointer variable that has no initial address should be explicitly initialized to
`NULL`.
This practice helps prevent undefined behavior caused by dereferencing uninitialized pointers.
The rule above about leaving statics and globals alone still holds: those already start as null
pointers, and writing the initializer out only obscures which of them the code means to set later.

Static analysis runs over the whole tree before each build and warns about a variable used before it
is initialized, which is the bug this section exists to prevent.

### Control structures

Try to make the control flow easy to follow.
Avoid long convoluted logic expressions; try to split them where possible (into inline functions,
separate if-statements, etc).

The control structure keyword and the expression in the brackets should be separated by a single
space.
The opening curly bracket shall be in the same line, also separated by a single space.
Example:

```c
    for (;;) {
        obj = get_first();
        while ((obj = get_next(obj))) {
            ...
        }
        if (done)
            break;
    }
```

A loop with an empty body carries an explicit pair of brackets, so that neither a reader nor
`-Wempty-body` has to decide whether the semicolon was a typo:
```c
    while (!ready()) {}   /* OK */
    while (!ready());     /* Wrong */
```

Do not add inner spaces around the brackets.
There should be one space after the semicolon when `for` has expressions:
```c
    for (unsigned i = 0; i < ARRAY_SIZE(items); i++) {
        ...
    }
```

#### Avoid unnecessary nesting levels

It is generally preferred to place the shorter clause (measured in lines of code) first in `if` and
`else if` statements.
Long clauses can distract the reader from the core decision-making logic, making the code harder to
follow.
By placing the shorter clause first, the decision path becomes clearer and easier to understand,
which can help reduce bugs.

Avoid nesting `if`-`else` statements deeper than two levels.
Instead, consider using function calls or `switch` statements to simplify the logic and enhance
readability.
Deeply nested `if`-`else` statements often indicate a complex and fragile state machine
implementation, which can be refactored into a safer and more maintainable structure.

For example, avoid this:
```c
int inspect(obj_t *obj)
{
    if (cond) {
        ...
        /* long code block */
        ...
        return 0;
    }
    return -1;
}
```

Instead, consider this approach:
```c
int inspect(obj_t *obj)
{
    if (!cond)
        return -1;
    ...
    return 0;
}
```

However, be careful not to make the logic more convoluted in an attempt to simplify nesting.

### `if` statements

Curly brackets and spacing follow the K&R style:
```c
    if (a == b) {
        ...
    } else if (a < b) {
        ...
    } else {
        ...
    }
```

Simple and succinct one-line `if` statements may omit curly brackets:
```c
    if (!valid)
        return -1;
```

However, do prefer curly brackets with multi-line or more complex statements.
If one branch uses curly brackets, then all other branches shall use the curly brackets too.

Wrap long conditions to the if-statement indentation adding extra 4 spaces:
```c
    if (some_long_expression &&
        another_expression) {
        ...
    }
```

#### Avoid redundant `else`

Avoid:
```c
    if (flag & F_FEATURE_X) {
        ...
        return 0;
    } else {
        return -1;
    }
```

Consider:
```c
    if (flag & F_FEATURE_X) {
        ...
        return 0;
    }
    return -1;
```

### `switch` statements

Switch statements should have the `case` blocks at the same indentation level, e.g.:
```c
    switch (expr) {
    case A:
        ...
        break;
    case B:
        /* fallthrough */
    case C:
        ...
        break;
    }
```

If the case block does not break, then it is strongly recommended to add a comment containing
"fallthrough" to indicate it.
Modern compilers can also be configured to require such comment (see gcc `-Wimplicit-fallthrough`).
Alternatively, consider using C23 `[[fallthrough]]` declaration.

### Function definitions

The opening and closing curly brackets shall also be in the separate lines (K&R style).

```c
ssize_t hex_write(FILE *stream, const void *buf, size_t len)
{
    ...
}
```

Do not use old K&R style C definitions.
A function that takes no parameters is declared and defined with `(void)`, never with empty
parentheses:
```c
int32_t get_status(void);  /* OK */
int32_t get_status();      /* Wrong: declares an unspecified parameter list, not zero parameters */
```

Every function reachable from outside its translation unit needs a prototype in the matching header.
Everything else is `static`.

Introduced in C99, `restrict` is a pointer qualifier that informs the compiler no other pointer will
access the same object during its lifetime, enabling optimizations such as vectorization.
Violating this assumption leads to undefined behavior.
Use `restrict` judiciously.

For function parameters, place one space after each comma, except at the end of a line.

### Function-like macros

When using function-like macros (parameterized macros), adhere to the following guidelines:
* For expression macros, enclose the entire macro body in parentheses.
* Surround each parameter usage with parentheses.
* Limit the use of each parameter to no more than once within the macro to avoid unintended side
  effects.
* Never include control flow statements (e.g., `return`) within a macro.
* If the macro involves multiple statements, encapsulate them within a `do`-`while (0)` construct
  instead of parentheses.

For example:
```c
#define SET_POINT(p, x, y)      \
    do {                        \
        (p)->px = (x);          \
        (p)->py = (y);          \
    } while (0)
```

While the extensive use of parentheses, as shown above, helps minimize some risks, it cannot prevent
issues like unintended double increments from calls such as `MAX(i++, j++)`.

Other risks associated with macros include comparing signed and unsigned data or testing
floating-point values.
Additionally, macros are not visible at runtime, making them impossible to step into with a
debugger.
Therefore, use them with caution.

In general, macro names are typically written in all capitals, except in cases where readability is
improved by using lowercase.
For example:
```c
#define countof(a)   (sizeof(a) / sizeof(*(a)))
#define lengthof(s)  (countof(s) - 1)
```

Although all capitals are generally preferred for constants, lowercase can be used for function-like
macros to improve readability.
These function-like macros do not share the same namespace concerns as other macros.

For example, consider the implementation of a simple memory allocator.
An arena can be represented by a memory buffer and an offset that begins at zero.
To allocate an object, record the pointer at the current offset, advance the offset by the size of
the object, and return the pointer.
Additional considerations, such as alignment and checking for available space, are also required.
```c
#define new(a, n, t)  alloc(a, n, sizeof(t), _Alignof(t))

typedef struct {
    char *begin, *end;
} arena_t;

static void *alloc(arena_t *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align)
{
    ptrdiff_t pad = -(uintptr_t)a->begin & (align - 1);
    assert(count < (a->end - a->begin - pad) / size);

    void *result = a->begin + pad;
    a->begin += pad + (count * size);
    return memset(result, 0, count * size);
}
```

Using the `new` macro helps prevent several common errors in C programs.
If types are mixed up, the compiler generates errors or warnings.
Moreover, naming a macro `new()` does not conflict with variables or fields named `new`, because the
macro form does not resemble a function call.

### Preprocessor directives

Prefer `#if defined(X)` over `#ifdef X`, since only the former composes with `&&`, `||`, and `!`
without rewriting the directive when a second condition appears.

Annotate `#else` and `#endif` with the condition they close.
A conditional block long enough to scroll is a conditional block whose `#endif` is otherwise
unattributable:
```c
#if defined(__aarch64__)
/* ... */
#else /* defined(__aarch64__) */
/* ... */
#endif /* !defined(__aarch64__) */
```

Do not indent the `#` of a nested directive.
The nesting is already visible in the conditions themselves, and a leading-space form is not
accepted by every preprocessor in equal measure.

### Use `const` and `static` effectively

The `static` keyword should be used for any variables that do not need to be accessible outside the
module where they are declared.
This is particularly important for global variables defined in C files.
Declaring variables and functions as `static` at the module level protects them from external
access, reducing coupling between modules and improving encapsulation.

For functions that do not need to be accessible outside the module, use the `static` keyword.
This is especially important for private functions, where `static` should always be applied.

For example:
```c
static bool verify_range(uint16_t x, uint16_t y);
```

The `const` keyword is essential for several key purposes:
* Declaring variables that should not change after initialization.
* Defining fields within a `struct` that must remain immutable, such as those in memory-mapped I/O
  peripheral registers.
* Serving as a strongly typed alternative to `#define` for read-only variables.

For example, instead of using:
```c
#define MAX_SKILL_LEVEL (100U)
```

Use:
```c
const uint8_t max_skill_level = 100;
```

Maximizing the use of `const` provides the advantage of compiler-enforced protection against
unintended modifications to data that should be read-only, thereby enhancing code reliability and
safety.

Additionally, when one of your function arguments is a pointer to data that will not be modified
within the function, you should use the `const` keyword.
This is particularly useful when comparing a character array with predefined strings without
altering the array's contents.

For example:
```c
static bool is_valid_cmd(const char *cmd);
```

### Object abstraction

Objects are often "emulated" by the C programmers with a `struct` and its "public API".
To enforce the information hiding principle, it is a good idea to define the structure in the source
file (translation unit) and provide only the _declaration_ in the header.
For example, `obj.c`:

```c
#include "obj.h"

struct obj {
    int value;
    ...
};

obj_t *obj_create(void)
{
    return calloc(1, sizeof(obj_t));
}

void obj_destroy(obj_t *obj)
{
    free(obj);
}
```

With an example `obj.h`:
```c
#pragma once

typedef struct obj obj_t;

obj_t *obj_create(void);
void obj_destroy(obj_t *);
```

Headers use `#pragma once`.
Every compiler this project targets supports it, and it removes a class of bugs that hand-written
guards invite: a misspelled macro, or the same guard name copied into a second header.
Note also that a guard spelled `_OBJ_H_` would be doubly wrong, since a leading underscore followed
by an uppercase letter is reserved for the implementation.

Such structuring will prevent direct access of the `obj_t` members outside the `obj.c` source file.
The implementation (of such "class" or "module") may be large and abstracted within separate source
files.
In such case, consider separating structures and "methods" into separate headers (think of different
visibility), for example `obj_impl.h` (private) and `obj.h` (public).

Consider `crypto_impl.h`:
```c
#pragma once

#if !defined(CRYPTO_PRIVATE)
#error "only to be used by the crypto modules"
#endif

#include "crypto.h"

struct crypto {
    crypto_cipher_t cipher;
    void *key;
    size_t key_len;
    ...
};
```

And `crypto.h` (public API):

```c
#pragma once

typedef struct crypto crypto_t;

crypto_t *crypto_create(crypto_cipher_t);
void crypto_destroy(crypto_t *);
...
```

### Include order

A source file includes system headers first, then project headers, each group separated by a blank
line:
```c
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "core/guest.h"
#include "syscall/internal.h"
```

A `.c` file includes its own header among the project headers, so that a header missing one of its
own dependencies fails in the translation unit that owns it rather than in whichever caller happens
to include it second.
Headers include what they use and nothing more; prefer a forward declaration when the full
definition is not needed.

Never include a `.c` file from another `.c` file.

### Use reasonable types

Use `unsigned` for general iterators; use `size_t` for general sizes; use `ssize_t` to return a size
which may include an error.
Of course, consider possible overflows.

Avoid using fixed-width types like `uint8_t`, `uint16_t`, or other smaller integer types for general
iterators or similar cases unless there is a specific need for size-constrained operations, such as
in fixed-width data processing or resource-limited environments.

C has rather peculiar _type promotion rules_ and unnecessary use of sub-word types might contribute
to a bug once in a while.

Boolean variables should be declared using the `bool` type.
Non-Boolean values should be converted to Boolean by using relational operators (e.g., `<` or `!=`)
rather than by casting.

For example:
```c
#include <stdbool.h>
...
bool inside = (value < expected_range);
```

### Dynamic memory

Do not use variable-length arrays.
A length that a caller controls becomes a stack extension the compiler cannot bound, and the failure
mode is a corrupted frame rather than a null return.
Allocate on the heap and check the result.

Size an allocation from the object it will hold, not from a type name repeated at the call site.
Written this way, the expression stays correct when the declaration of `arr` changes:
```c
int32_t *arr = malloc(sizeof(*arr) * count);  /* OK */
int32_t *arr = malloc(sizeof(int32_t) * count);  /* Fragile: repeats the type */
```

Do not cast the result of `malloc` or any other function returning `void *`.
In C the conversion is implicit, and the cast only hides a missing declaration.

After passing a pointer to `free`, set it to `NULL` when the variable remains in scope.
This turns a later double free or use-after-free into a null dereference at the point of the bug.

### Embrace portability

#### Byte-order

Do not assume x86 or little-endian architecture.
Use endian conversion functions for operating the on-disk and on-the-wire structures or other cases
where it is appropriate.

#### Types

Do not assume a particular 32-bit or 64-bit architecture; for example, do not assume the size of
`long` or `unsigned long`.
Instead, use `int64_t` or `uint64_t` for 8-byte integers.

Fixed-width types, such as `uint32_t`, are particularly useful when memory size is critical, as in
embedded systems, communication protocols requiring specific data sizes, or when interacting with
hardware registers that require precise bit-width operations.
In these scenarios, fixed-width types ensure consistent behavior across different platforms and
compilers.

Do not assume `char` is signed; its signedness is implementation-defined and varies by platform and
compiler (e.g., unsigned by default on many Arm toolchains).

Avoid defining bit-fields within signed integer types.
Additionally, do not use bitwise operators (such as `&`, `|`, `~`, `^`, `<<`, and `>>`) on signed
integer data.
Refrain from combining signed and unsigned integers in comparisons or expressions, as this can lead
to unpredictable results.

When using `#define` to declare decimal constants, append a `U` to ensure they are treated as
unsigned.
For example:
```c
#define SOME_CONSTANT (6U)

uint16_t unsigned_a = 6;
int16_t  signed_b = -9;
if (unsigned_a + signed_b < 4) {
    /* This block might appear logically correct, as -9 + 6 is -3 */
    ...
}
/* but compilers with 16-bit int may legally interpret it as (0x10000 - 9) + 6. */
```

It is important to note that certain aspects of manipulating binary data within signed integer
containers are implementation-defined behaviors according to ISO C standards.
Additionally, mixing signed and unsigned integers can lead to data-dependent results, as
demonstrated in the example above.

Use C99 macros for constant prefixes or formatting of the fixed-width types.

Use:
```c
#define SOME_CONSTANT (UINT64_C(1) << 48)
printf("val %" PRIu64 "\n", SOME_CONSTANT);
```

Do not use:
```c
#define SOME_CONSTANT (1ULL << 48)
printf("val %lld\n", SOME_CONSTANT);
```

#### Avoid unaligned access

Avoid assuming that unaligned access is safe.
It is not safe on architectures like Arm, POWER, and others, where it may cause a fault.
Additionally, even on x86, unaligned access can be slower.

#### Structures and unions

Care should be taken to prevent the compiler from inserting padding bytes within `struct` or `union`
types, as this can affect memory layout and portability.
To control padding and alignment, consider using structure packing techniques specific to your
compiler.

Additionally, take precautions to ensure that the compiler does not alter the intended order of bits
within bit-fields.
This is particularly important when working with hardware registers or communication protocols where
bit order is crucial.

According to the C standard, the layout of structures, including padding and bit-field ordering, is
implementation-defined, meaning it can vary between different compilers and platforms.
Therefore, it is essential to verify that the structure's layout meets your expectations, especially
when writing portable code.

For example:
```c
typedef struct {
    uint16_t count;         /* offset 0 */
    uint16_t max_count;     /* offset 2 */
    uint16_t unused0;       /* offset 4 */
    uint16_t enable    : 2; /* offset 6 bits 15-14 */
    uint16_t interrupt : 1; /* offset 6 bit 13     */
    uint16_t unused1   : 7; /* offset 6 bits 12-6  */
    uint16_t complete  : 1; /* offset 6 bit 5      */
    uint16_t unused2   : 4; /* offset 6 bits 4-1   */
    uint16_t periodic  : 1; /* offset 6 bit 0      */
} mytimer_t;

_Static_assert(sizeof(mytimer_t) == 8,
               "mytimer_t struct size incorrect (expected 8 bytes)");
```

To enhance portability, use standard-defined types (e.g., `uint16_t`, `uint32_t`) and avoid relying
on compiler-specific behavior.
Where precise control over memory layout is required, such as in embedded systems or when
interfacing with hardware, always verify the structure size and layout using static assertions.

#### Avoid extreme portability

Unless programming for micro-controllers or exotic CPU architectures, focus on the common
denominator of the modern CPU architectures, avoiding the very maximum portability that can make the
code unnecessarily cumbersome.

Some examples:
* It is fair to assume `sizeof(int) == 4` since it is the case on all modern mainstream
  architectures.
  PDP-11 era is long gone.
* Using `1U` instead of `UINT32_C(1)` or `(uint32_t) 1` is also fine.
* It is fair to assume that `NULL` is matching `(uintptr_t) 0` and it is fair to `memset()`
  structures with zero.
  Non-zero `NULL` is for retro computing.

#### Zero-based numbering

Generally, stick with zero-based numbering and 0 ≤ i < N intervals, unless there is a very
compelling reason not to.
It is universally accepted by the C developers.
Also, see EWD 831 (Dijkstra, 1982).

## Before Submitting

Run these locally before opening a pull request:

| Command | What it covers |
|---------|----------------|
| `make check-format` | comment reflow, clang-format compliance, shellcheck over every script the repository carries, syscall dispatch table consistency, test-matrix skip lists |
| `make check` | unit tests, the busybox suite, syscall test coverage, the EINTR restart contract, lock-order documentation |
| `make verify` | the Frama-C proof obligations behind `src/proved/` |
| `bash tests/test-matrix.sh all` | the guest matrix; the `elfuse-aarch64` lane must stay green |

When the comment-width gate fails it names the fix: run `make indent`, or `commentflow --diff
<file>` to read one file's reflow before taking it.

### What CI checks, and how it differs

CI runs some of these targets and reimplements others.
`build.yml` invokes `make check` and `bash tests/test-matrix.sh all` directly, and `verify.yml` runs the
proofs.
Formatting is the exception: CI calls the `.ci/` scripts rather than `make check-format`, and narrows
several steps to the files a pull request touched.
A local run is therefore the wider net for formatting and the same net for the rest.
CI is also the only run that happens on a Linux host.

The layers do not cover the same ground:
* `.ci/check-format.sh` is clang-format alone, over the C sources in `src/` and `tests/`.
* `.ci/check-commentflow.sh` is the comment-width gate.
  That script owns the file list for both callers, so `make check-format` and CI cover the same set:
  C and headers, every shell script, and the assembly sources.
  CI installs a checksum-pinned commentflow release, for the same reason clang-format is held at one
  version.
* shellcheck runs over `.ci/*.sh` only.
  `make check-format` covers every script the repository carries, tracked or merely
  untracked-and-unignored, which is the wider net, and today that wider net is red:
  several scripts under `tests/` carry pre-existing warnings, which is why CI narrows the step
  rather than gating on them.
  The bar for a pull request is that it adds no new warning to a script it touches, not that the
  target passes outright.
* Nothing gates `shfmt` or `black`.
  Their rules are conventions a reviewer applies, not a check that will catch you.
* cppcheck runs over the C sources (`.ci/check-cppcheck.sh`).

CI also rejects a few things no formatter reports:
* Banned libc calls anywhere in `src/`: `gets`, `sprintf`, `vsprintf`, `strcpy`, `stpcpy`, `strcat`,
  `atoi`, `atol`, `atoll`, `atof`, `mktemp`, `tmpnam`, `tempnam`.
  Use the bounded or checked form instead.
* `#undef` or `#define` of `_FORTIFY_SOURCE 0` or `__SSP__`, which would disable a hardening default
  for the whole translation unit.
* A tracked file with no trailing newline.
* A new `dispatch.tbl` entry that no test references.
* A new file-scope mutex that the lock-ordering block at the top of `src/syscall/internal.h` does
  not name.

## Git Commit Style

Effective version control is critical to modern software development.
Git's powerful features, such as granular commits, branching, and a versatile staging area, offer
unparalleled flexibility.
However, this flexibility can sometimes lead to disorganized commit histories and merge conflicts if
not managed with clear, consistent practices.

By committing often, writing clear messages, and adhering to a common workflow, developers can not
only reduce the potential for errors but also simplify collaboration and future maintenance.
We encourage every team to tailor these best practices to their specific needs while striving for a
shared standard that promotes efficiency and code quality.

Below are the detailed guidelines that build on these principles.
* Group Related Changes Together: Each commit should encapsulate a single, coherent change. e.g., if
  you are addressing two separate bugs, create two distinct commits.
  This approach produces focused, small commits that simplify understanding, enable quick rollbacks,
  and foster efficient peer reviews.
  By taking advantage of Git's staging area and selective file staging, you can craft granular
  commits that make collaboration smoother and more transparent.
* Commit Frequently: Making commits often ensures that your changes remain concise and logically
  grouped.
  Frequent commits not only help maintain a clean history but also allow you to share your progress
  with your teammates regularly.
  This regular sharing keeps everyone in sync, minimizes merge conflicts, and promotes a
  collaborative environment where integration happens seamlessly.
* Avoid Committing Work in Progress: Only commit code when a logical component is in a stable,
  ready-to-integrate state.
  Break your feature's development into manageable segments that reach a functional milestone
  quickly, so you can commit regularly without compromising quality.
  If you feel the urge to commit merely to clear your working directory for actions like switching
  branches or pulling changes, use Git's stash feature instead.
  This practice helps maintain a stable repository and ensures that your team reviews well-tested,
  coherent code.
* Test Your Code Before Committing: Before committing, ensure that your code has been thoroughly
  tested.
  Rather than assuming your changes are ready, run comprehensive tests to confirm they work as
  intended without unintended side effects.
  Testing is especially critical when sharing your code with others, as it maintains the overall
  stability of the project and builds trust among collaborators.
* Utilize Branches for Parallel Development: Branches are a powerful tool that enables developers to
  isolate different lines of work, whether you are developing new features, fixing bugs, or
  exploring innovative ideas.
  By using branches extensively, you can work on your tasks independently and merge only after
  careful review and testing.
  This not only keeps the main branch stable but also encourages collaborative code reviews and a
  more organized integration process.

Clear and descriptive commit messages are crucial for maintaining a transparent history of changes
and for facilitating effective debugging and tracking.
Please adhere to the guidelines outlined in [How to Write a Git Commit
Message](https://cbea.ms/git-commit/).
1. Separate the subject from the body with a blank line.
2. Limit the subject line to 50 characters.
3. Capitalize the subject line.
4. Do not end the subject line with a period.
5. Use the imperative mood in the subject line.
6. Wrap the body at 72 characters.
7. Use the body to explain what and why, not how.

A body line may exceed 72 characters when everything past that column is part
of one word containing a URL, since a URL cannot be wrapped.

An example (derived from Chris' blog post) looks like the following:
```text
Summarize changes in around 50 characters or less

More detailed explanatory text, if necessary. Wrap it to about 72
characters or so. In some contexts, the first line is treated as the
subject of the commit and the rest of the text as the body. The
blank line separating the summary from the body is critical (unless
you omit the body entirely); various tools like `log`, `shortlog`
and `rebase` can get confused if you run the two together.

Explain the problem that this commit is solving. Focus on why you
are making this change as opposed to how (the code explains that).
Are there side effects or other unintuitive consequences of this
change? Here's the place to explain them.

Further paragraphs come after blank lines.

- Bullet points are okay, too

- Typically a hyphen or asterisk is used for the bullet, preceded
  by a single space, with blank lines in between, but conventions
  vary here

If you use an issue tracker, put references to them at the bottom,
like this:
Close #123
```

Another illustration of effective practice.
```text
commit f1775422bb5a1aa6e79a685dfa7cb54a852b567b
Author: Jim Huang <jserv@ccns.ncku.edu.tw>
Date:   Mon Feb 24 13:08:32 2025 +0800

    Introduce CPU architecture filtering in scheduler

    In environments with mixed CPU architectures, it is crucial to ensure
    that an instance runs only on a host with a compatible CPU
    type, preventing, for example, a RISC-V instance from being scheduled on
    an Arm host.

    This new scheduler filter enforces that requirement by comparing an
    instance's architecture against the host's allowed architectures. For
    the libvirt driver, the host's guest capabilities are queried, and the
    permitted architectures are recorded in the permitted_instances_types
    list within the host's cpu_info dictionary.

    The filter systematically excludes hosts that do not support the
    instance's CPU architecture. Additionally, RISC-V has been added to the
    set of acceptable architectures for scheduling.

    Note that the CPU architecture filter is disabled by default.
```

The above is a clear, unformatted description provided in plain text.

In addition, this project expects contributors to follow these additional rules:
* If there is important, useful, or essential conversation or information, include a reference or
  copy it.
* Do not write single-word commits.
  Provide a descriptive subject.
* Avoid using abusive words.
* Avoid using backticks in commit subjects.
  Backticks can be easily confused with single quotes on some terminals, reducing readability.
  Plain text or single quotes provide sufficient clarity and emphasis.
* Avoid using parentheses in commit subjects.
  Excessive use of parentheses "()" can clutter the subject line, making it harder to quickly grasp
  the essential message.

The seven rules above are enforced by `scripts/git-commit-msg.sh`, which the
"Commit messages" step of the `Lint (Linux)` job in `.github/workflows/lint.yml`
runs over every commit in a pull request. See that workflow for the rest of the
checks a pull request has to clear.

The first `make` in a fresh clone installs the same script as a local hook, so
a message is rejected while it is still cheap to rewrite rather than after the
push. Alongside it go a pre-commit hook that checks staged formatting, comment
reflow, banned APIs and whitespace, and a pre-push hook that validates every
unpublished commit. A hook you already wrote is never replaced.
`make uninstall-hooks` removes them, `make install-hooks` puts them back. The
hooks only move the feedback earlier; CI runs the same checks either way.

Two rules cannot be decided by a script. Imperative mood is checked by
rejecting the past-tense, third-person and gerund forms of common verbs, so an
unlisted verb passes. "What and why, not how" is checked only for a body that
opens by announcing the mechanism. Both are guidance a reviewer still applies.

## References
* [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html)
* Tilen Majerle, [Recommended C style and coding rules](https://github.com/MaJerle/c-code-style)
* 1999, Brian W.
  Kernighan and Rob Pike, The Practice of Programming, Addison-Wesley.
* 1993, Bill Shannon, [C Style and Coding Standards for
  SunOS](https://devnull-cz.github.io/unix-linux-prog-in-c/cstyle.ms.pdf)

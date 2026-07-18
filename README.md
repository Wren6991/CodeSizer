# CodeSizer

*Why is that binary so big?*

## What

CodeSizer is a static code size profiling tool.

In size-focused embedded firmware development it's common for the final binary to be heavily inlined and LTO'd. A single function symbol may consist of dozens of inlinees. CodeSizer uses `objdump` and `addr2line` to unwind the inline call stack at every instruction address, so code size can be attributed to the correct node in the call tree.

The output is a static HTML report file, with a small amount of JavaScript for UI features like toggling expand/collapse of the tree view.

## How

From the interactive help:

```
usage: codesizer.py [-h] [--cross-prefix CROSS_PREFIX] [--section SECTION]
                    elf output

Analyse static code size of an ELF file. Disassemble via objdump, unwind inline
call stacks via addr2line, and emit a static HTML report.

positional arguments:
  elf                   input ELF file
  output                output HTML file

options:
  -h, --help            show this help message and exit
  --cross-prefix CROSS_PREFIX
                        prefix for objdump and addr2line (default: riscv32-unknown-
                        elf-)
  --section, -j SECTION
                        Specify ELF section. Pass multiple times for multiple
                        sections. If unspecified, .text is used.
```

The correct toolchain must be present on your `$PATH` with the given prefix, or you must specify a full file path to the toolchain binaries.

For example:

* If you've installed the `gcc-arm-none-eabi` package on Ubuntu, then use `--cross-prefix=arm-none-eabi-`.

* If you've installed a `riscv-gnu-toolchain` build at `/opt/riscv/gcc15`, then use `--cross-prefix=/opt/riscv/gcc15/bin/riscv32-unknown-elf-`.

## Example Output

TODO link to release

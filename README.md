# STM32 Binary Memory Analysis

This Python script uses the linker script and the built ELF file to create a memory report. This memory report outlines the total FLASH and RAM usage. This script is specifically made for STM projects as I couldn't find a CLI alternative for the "Build Analyzer" feature STM32CubeIDE has. It can be plugged straight into your CI/CD pipelines to generate a memory report at the end of the firmware build.

## How to set this up?

For this script to work, you need to enable certain post-build scripts in your STM32CubeIDE.

1. Go to `Project -> Properties -> C/C++ Build -> Settings -> Build steps`.
2. Here, in the Post-build-steps add this command:
    ```sh
    objdump ${ProjName}.elf -h >release_objdump.txt
    ```
    for release configuration and
    ```sh
    objdump ${ProjName}.elf -h >debug_objdump.txt
    ```
    for debug configuration.

## Run the script

```sh
python memory-usage-calculator.py --linker path/to/linker_script.ld --objdump path/to/objdump_output.txt
```

Additional debug logs can be obtained using the `--debug` flag:

```sh
python memory-usage-calculator.py --linker path/to/linker_script.ld --objdump path/to/objdump_output.txt --debug
```
## How it works?
The script initially pareses through the linker script and maps the sections to two directories - FLASH and RAM.

Using the `objdump` output , the sections are populated with sizes. 

## Future of this script

The script is entirely vibe-coded, so there could be a lot of places for optimization and improvement. I intend to port this to `Go` (for fun!).


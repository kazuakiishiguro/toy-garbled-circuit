# Implementation of Yao's Garbled Circuit

This project implements Yao's Garbled Circuit and is inspired by [this repository](https://github.com/Giapppp/toy-garbled-circuit).

## Prerequisites

- Ensure you have a compiler with OpenSSL support installed (e.g., `gcc`).
- Ensure OpenSSL development libraries are installed on your system (e.g., `libssl-dev` on Debian-based systems).

## Building the Project

To compile the project, you can use the provided `Makefile`. Open a terminal and run the following command:

```bash
make
```

This will compile the source code and produce an executable named `garbled_circuit`.

## Usage

You can run the program in different modes: as a garbler or as an evaluator. Additionally, you can run tests to verify functionality.

### Running as Garbler

To run the program as a garbler:

```bash
./garbled_circuit garbler <bit> <gate>
```

- Replace `<bit>` with `0` or `1`.
- Replace `<gate>` with `AND` or `XOR`.
- You will be prompted to input four 32-digit hexadecimal keys.

### Running as Evaluator

To run the program as an evaluator:

```bash
./garbled_circuit evaluator <bit> <gate>
```

- Replace `<bit>` with `0` or `1`.
- Replace `<gate>` with `AND` or `XOR`.

### Running Tests

To run tests, use:

```bash
make test
```

This will execute the program in test mode.

## Cleaning Up

To remove the compiled executable and object files, run:

```bash
make clean
```

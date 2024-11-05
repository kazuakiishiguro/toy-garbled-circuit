Implementation of Yao's Gabled Circuit.
- inspired by (https://github.com/Giapppp/toy-garbled-circuit)

Usage:
- Compile the code using a compiler with `OpenSSL` support, for example:
```bash
gcc -o garbled_circuit main.c -lcrypto
```

- Running the program:
  - As Garbler:
  ```bash
  ./garbled_circuit garbler <bit> <gate>
  ```
    - Replace `<bit>` with `0` or `1`.
    - Replace `<gate>` with `AND` or `XOR`.
    - Input four 32-digit hexadecimal keys when prompted.

  - As Evaluator:
  ```bash
  ./garbled_circuit evaluator <bit> <gate>
  ```
    - Replace `<bit>` with `0` or `1`.
    - Replace `<gate>` with `AND` or `XOR`.

Note:
> The program randomly generates the other party's bit and keys when acting as the evaluator, and requires user input for keys when acting as the garbler.

Test:
```bash
./garbled_circuit test
```

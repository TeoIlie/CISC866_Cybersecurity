### Intro

This repo holds code related to the CISC866 Cybersecurity course.

### Assignment 1: Decryption task

The command to compile and run the code `brute_force_test.c`:

```zsh
gcc -o brute_force_test brute_force_test.c -lssl -lcrypto -fsanitize=address | ./brute_force_test
```


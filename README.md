sys-crypt
=======

- Implemented new System Call in Linux 3.2 to perform encrypted file I/O

- This system consists of a user level program and a new system call. User level program provides an unencrypted data buffer as an input to the system call which writes it in a file in an encrypted format. Similarly, user level program can read from the encrypted file and display it to user in unencrypted format

- Used C, Linux Kernel Module programming and CryptoAPI
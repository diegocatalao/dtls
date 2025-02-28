# Secure DTLS Server

This project implements a DTLS (Datagram Transport Layer Security) server for
secure communication over UDP using OpenSSL. It connects to a DTLS server and
performs authentication using X.509 certificates.

## 📌 Requirements

- **Operating System**: Linux or macOS (Windows may require modifications)
- **Compiler**: GCC (minimum `gcc 7.5.0`) or Clang

### Install Dependencies

For Debian/Ubuntu:

```sh
$ sudo apt update
$ sudo apt install -y libssl-dev build-essential
```

For macOS (with Homebrew):

```bash
brew install gcc make openssl
```

### Build

To build the DTLS server, run:

```bash
$ make && make -C tools
```

### Usage

Run the DTLS server in the first terminal:

```bash
$ ./bin/dtlss 127.0.0.1 5684
```

On another terminal, run the command with OpenSSL:

```bash
$ echo "hallo\0" | openssl s_client -connect 127.0.0.1:5684 -dtls1_2 -msg -debug
```

### Copyright and License

Code released under the MIT License. Docs released under Creative Commons.

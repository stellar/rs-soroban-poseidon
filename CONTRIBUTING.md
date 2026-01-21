# Contributing

Contributions are welcome to soroban-poseidon. Please discuss issues to be solved
and potential solutions on issues ahead of opening a pull request.

## Development Environment Setup

Install rustup:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install rust stable:
```
rustup install stable
rustup +stable target add wasm32v1-none
```

## Command Cheatsheet

See the `Makefile` for all the common commands you might need.

Format code:
```
make fmt
```

Build library and test contracts:
```
make build
```

Run tests:
```
make test
```

Open docs locally:
```
make doc
```

Check code (includes clippy):
```
make check
```

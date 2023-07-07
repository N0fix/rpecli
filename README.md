# RPECLI

Rust blazing fast alternative to [pecli](https://github.com/Te-k/pecli). `pecli` is a great tool, but it uses pefile, which is a bit slow to load PE executables, especialy when dealing with a whole lot of executables. This project aims at being a faster alternative to pecli.

This project currently relies on the [`exe`](https://crates.io/crates/exe) create, that was created with malware parsing in mind.

## Build
```
cargo build --release
```

## Install
```
cargo install rpecli
```
or locally :
```
cargo install --path .
```

## Usage
```
rpecli info path_to_exe
```
```
rpecli --help
```

## TODO
- Refacto of some parts
- Credits of portions of code are missing (I think I'm missing references to pelite)
- Error handling
- More commands
- Possiblity to dump resources
- Color on sections
- Feature to handle comparing some fields between multiple binaries to help finding header similarities

### Optimisation notes

Callgrind indicates that most of the time is spent hashing stuff (sha/md5) and rendering tables.

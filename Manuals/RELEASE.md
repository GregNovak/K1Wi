# Opus Release Checklist

Release: **K1Wi**  
Version: **v0.99 RC1**

## Build

- [x] `make clean && make` completes successfully
- [x] No compiler errors
- [x] No compiler warnings
- [x] Binary generated at `bin/opus`

## Testing

- [x] Regression suite passes
- [x] Negative CLI tests pass
- [x] Sanitizer build completes
- [x] Sanitizer regression run passes

## Verified Commands

- [x] `opus --version`
- [x] `opus help`
- [x] `opus string`
- [x] `opus extract`
- [x] `opus lyzer`
- [x] `opus entropy`
- [x] `opus elf`
- [x] `opus PIECALC`
- [x] `opus rsa`

## Documentation

- [x] README created
- [x] CHANGELOG created
- [x] RELEASE checklist created
- [ ] User manual completed
- [ ] Command examples reviewed
- [ ] Install instructions reviewed

## Release Tasks

- [ ] Update version to v1.0 when ready
- [ ] Run final clean build
- [ ] Run final sanitizer build
- [ ] Run final regression suite
- [ ] Create git tag
- [ ] Create release archive
- [ ] Package source and binary


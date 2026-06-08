# K1wi Release Checklist

Release: **K1Wi**  
Version: **v0.99 RC1**

## Build

- [x] `make clean && make` completes successfully
- [x] No compiler errors
- [x] No compiler warnings
- [x] Binary generated at `bin/k1wi`

## Testing

- [x] Regression suite passes
- [x] Negative CLI tests pass
- [x] Sanitizer build completes
- [x] Sanitizer regression run passes

## Verified Commands

- [x] `k1wi --version`
- [x] `k1wi help`
- [x] `k1wi string`
- [x] `k1wi extract`
- [x] `k1wi lyzer`
- [x] `k1wi entropy`
- [x] `k1wi elf`
- [x] `k1wi PIECALC`
- [x] `k1wi rsa`

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


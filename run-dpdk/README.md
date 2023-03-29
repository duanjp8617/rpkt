# Run Testcases
1. Add the following lines to `~/.cargo/config`:
```shell
[target.x86_64-unknown-linux-gnu]
runner = 'sudo -E'
```

2. The testcases must be run within a single thread, so use the following command to run the test:
```shell
cargo test -- --test-threads=1
```

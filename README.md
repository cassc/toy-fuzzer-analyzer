# Usage

``` bash
cargo install --path . --profile release --force --locked
fuzzer_analyzer \
    --fuzzer-path /opt/my_fuzzer/mau-ityfuzz \
    --benchmark-base-dir /data/my_benchmarks \
    --output-dir ./results \
    --fuzz-timeout-seconds 60
```

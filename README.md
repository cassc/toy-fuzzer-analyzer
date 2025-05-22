# Usage

``` bash
# Only when using older Ubuntu
# sudo apt install libfontconfig1-dev -y

# Install binary
cargo install --path . --profile release --force --locked

# Compile the contracts
fuzzer_analyzer compile --solc-input-dir ../mau-ityfuzz/release/benchmarks/B1/sol/ --solc-output-dir b1 --list-file ../mau-ityfuzz/release/benchmarks/assets/B1.list

fuzzer_analyzer compile --solc-input-dir ../mau-ityfuzz/release/benchmarks/B3/sol/ --solc-output-dir b3 --list-file ../mau-ityfuzz/release/benchmarks/assets/B3.list



# Run the fuzzer
fuzzer_analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b1 \
    --output-dir ./results \
    --fuzz-timeout-seconds 10

# Plot the results
fuzzer_analyzer plot --output-dir ./results
```

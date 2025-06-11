# Usage

``` bash
# Only when using older Ubuntu
# sudo apt install libfontconfig1-dev -y

# Install binary
cargo install --path crates/mau-analyzer/ --profile release --force --locked

# Select or install solc version 0.4.25

# Compile the B1 contracts
mau-analyzer compile --solc-input-dir ./release/benchmarks/B1/sol/ \
  --solc-output-dir b1 \
  --list-file ./release/benchmarks/assets/B1.list

# Compile and generate ptx files for the B1 contracts (require running in the mau-ityfuzz docker container)
mau-analyzer compile --solc-input-dir ./release/benchmarks/B1/sol/ \
  --solc-output-dir b1 \
  --generate-ptx \
  --list-file ./release/benchmarks/assets/B1.list

# Compile and generate ptx files for the B3 contracts
mau-analyzer compile --solc-input-dir ./release/benchmarks/B3/sol/ \
  --solc-output-dir b3 \
  --list-file ./release/benchmarks/assets/B3.list \
  --solc-timeout-seconds 10 \
  --generate-ptx \
  --solc-binary ~/.solcx/solc-v0.4.25

# Run the fuzzer
export LD_LIBRARY_PATH=./runner/

# Run b1 contracts in CPU
mau-analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b1 \
    --output-dir ./b1-results \
    --fuzz-timeout-seconds 10

> Detailed execution logs can be found in /tmp/logs/mau-analyzer.log


# Run b1 contracts in GPU  (requires running in the mau-ityfuzz docker container)
mau-analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b1 \
    --output-dir ./b1-ptx-results \
    --use-ptx \
    --fuzz-timeout-seconds 10

# Run b3 contracts in CPU
mau-analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b3 \
    --output-dir ./b3-results \
    --fuzz-timeout-seconds 10

# Run b3 contracts in GPU
mau-analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b3 \
    --use-ptx \
    --output-dir ./b3-ptx-results \
    --fuzz-timeout-seconds 10


# Plot the results
mau-analyzer plot --output-dir ./results
```

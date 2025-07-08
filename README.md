# Usage

> Execution logs can be found in the `/tmp/logs/` folder.

## Test MAU

``` bash
# Only when using older Ubuntu
# sudo apt install libfontconfig1-dev -y

# Install binary
cargo install --path crates/mau-analyzer/ --profile release --force --locked

# Select or install solc version 0.4.25

# Or use docker image
git clone https://github.com/cassc/mau-ityfuzz
cd mau-ityfuzz
docker run --gpus all --name mau-ityfuzz-0611  -it -w /app -v $(pwd):/app augustus/mau-ityfuzz:20250529 /bin/bash

# Compile the B1 contracts
mau-analyzer compile --solc-input-dir ./release/benchmarks/B1/sol/ \
  --solc-output-dir b1 \
  --list-file ./release/benchmarks/assets/B1.list

# Compile and generate ptx files for the B1 contracts (require running in the mau-ityfuzz docker container)
mau-analyzer compile --solc-input-dir ./release/benchmarks/B1/sol/ \
  --solc-output-dir b1 \
  --generate-ptx \
  --list-file ./release/benchmarks/assets/B1.list

mau-analyzer compile --solc-input-dir ./solc_v8_noargs/ \
  --solc-output-dir solc_v8_noargs_data \
  --generate-ptx \
  --list-file ./solc_v8_noargs_smartian_format.json.meta


# Compile and generate ptx files for the B3 contracts
mau-analyzer compile --solc-input-dir ./release/benchmarks/B3/sol/ \
  --solc-output-dir b3 \
  --list-file ./release/benchmarks/assets/B3.list \
  --solc-timeout-seconds 10 \
  --generate-ptx \
  --solc-binary ~/.solcx/solc-v0.4.25

# Generate PTX files using the compiled binaries
mau-analyzer ptx --solc-output-dir b3

# Run the fuzzer
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/runner/

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


## Test ityfuzz


``` bash
cargo install --path crates/ityfuzz-analyzer/ --profile release --force --locked
ityfuzz-analyzer run -f ityfuzz -b b1 -o ityfuzz-output/timeout-30 --fuzz-timeout-seconds 30
# Running tests in 20 processes:
ityfuzz-analyzer run -f ityfuzz -b b1 -o ityfuzz-output/timeout-30 --fuzz-timeout-seconds 30 -j 20
ityfuzz-analyzer plot ityfuzz-output/timeout-30
```

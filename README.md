# Usage

``` bash
# Only when using older Ubuntu
# sudo apt install libfontconfig1-dev -y

# Install binary
cargo install --path . --profile release --force --locked

# Select or install solc version 0.4.25

# Compile and prepapre the B1 contracts
fuzzer_analyzer compile --solc-input-dir ./release/benchmarks/B1/sol/ \
  --solc-output-dir b1 \
  --generate-ptx \ # for generating ptx files. Need to run inside the mau-ityfuzz docker container
  --list-file ./release/benchmarks/assets/B1.list

# Compile and prepapre the B3 contracts
fuzzer_analyzer compile --solc-input-dir ./release/benchmarks/B3/sol/ --solc-output-dir ~/tmp/b3-processed --list-file ./release/benchmarks/assets/B3.list --solc-timeout-seconds 10 --solc-binary ~/.solcx/solc-v0.4.25



# Run the fuzzer
fuzzer_analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b1 \
    --output-dir ./b1-results \
    --use-ptx \
    --fuzz-timeout-seconds 10

fuzzer_analyzer run \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b3 \
    --output-dir ./b3-results \
    --fuzz-timeout-seconds 10


# Plot the results
fuzzer_analyzer plot --output-dir ./results
```

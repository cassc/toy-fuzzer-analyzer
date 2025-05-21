# Usage

``` bash
# On older ubuntu might require
# sudo apt install libfontconfig1-dev -y

cargo install --path . --profile release --force --locked

fuzzer_analyzer \
    --fuzzer-path ./mau-ityfuzz \
    --benchmark-base-dir b1 \
    --output-dir ./results \
    --fuzz-timeout-seconds 10
```

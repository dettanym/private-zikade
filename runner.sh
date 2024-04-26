#!/usr/bin/env bash

mkdir -p cache/gopath/{bin,src}
echo '*' > cache/.gitignore

docker run --rm -ti \
  -e HOME=/tmp \
  -v "$(pwd)/cache/gopath:/go" \
  -v "$(pwd):/code" \
  -w "/code" \
  --user "$(id -u):$(id -g)" \
  golang \
    go test \
      -test.v \
      - test.timeout 99999s \
      -test.bench '^\QBenchmark_PIR_for_Provider_Routing\E$' \
      -test.run '^$' \
      ./pir/... && \
    go test \
      -test.v \
      - test.timeout 99999s \
      -test.bench '^\Benchmark_PIR_for_Routing_Table\E$' \
      -test.run '^$' \
      ./pir/...
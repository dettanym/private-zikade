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
    #This will run our evaluation for peer routing
    # It will produce the first column of figures in Fig 1
    # Output will be written to the csv_results folder
    go test \
      -test.v \
      -test.timeout 99999s \
      -test.bench '^\QBenchmark_PIR_for_Routing_Table\E$' \
      -test.run '^$' \
      ./pir/... && \
    #This will run our evaluation for provider advertisements
    # It will produce the second column of figures in Fig 1
    # Output will be written to the csv_results folder
    go test \
      -test.v \
      -test.timeout 99999s \
      -test.bench '^\QBenchmark_PIR_for_Provider_Routing\E$' \
      -test.run '^$' \
      ./pir/... && \
    #This will evaluate the normalized RT and the original RT
    # for difference in the number of hops (i.e. convergence),
    # as decribed in S5.2 'Routing table with normalized buckets'
    # Output will go to stdout
    go test \
      -test.v \
      -test.timeout 99999s \
      -test.run '^\QTestRoutingNormVsTrie\E$' \
      ./internal/coord/
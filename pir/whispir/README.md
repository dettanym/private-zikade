# Generators for Automorphisms

This script is used to find the generators for the automorphisms. The script is heavily optimized to search the space very efficiently. It iterates over all pairs/triplets of generators, checks how many automorphisms they require to achieve the desired automorphisms, and stops early if they are too costly. The script is heavily parallelized using OpenMP so it has to be run using gcc.

## Requirements
- CMake
- C++ compiler
- OpenMP

## Build
```
mkdir build
cd build
cmake ..
make
```

## Run
It can in the following way for finding two or three generators, respectively.
```
./main 2
./main 3
```
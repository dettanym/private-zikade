This script simulates hashing into bins to derive the max load of a bin.

## Usage
```
g++ -fopenmp script.cpp -o script
./script scheme_name
```
Here `scheme_name` can be either `paillier` or `rlwe`.

## Output
The results are written in `simulation-scheme_name.csv`.
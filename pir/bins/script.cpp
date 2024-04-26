#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <fstream>
#include <omp.h>

using namespace std;

void run_max_load(bool isPaillier){
    uint64_t RUNS = ((uint64_t)1 << 30);

    uint64_t bins;
    uint64_t balls[] = {
        8192,
        16384,
        24576,
        32768,
        40960,
        49152,
        57344,
        65536,
        73728,
        81920,
        90112,
        98304,
        106496,
        114688,
        122880,
        131072,
        139264,
        147456,
        155648,
        163840,
        172032,
        180224,
        188416,
        196608
    };
   if (isPaillier) {
        bins = 256;
   }
   else {
        bins = 4096;
   }
    int pairs = 24;
    int answer[pairs];
    for (int i=0;i<pairs;i++){
        answer[i] = 0;
    }
    uint64_t runned = 0;
    uint64_t milestone = 1;
    #pragma omp parallel
    {
        std::random_device rd;  //Will be used to obtain a seed for the random number engine
        std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
        #pragma omp for
        for (int run=0;run < RUNS;run++){
            if (runned == milestone){
                #pragma omp critical
                {
                    if (runned == milestone){
                        cout << "Reached the mile stone " << milestone << endl;
                        milestone *= 2;
                        ofstream result_file;
                        string filename;
                        if (isPaillier) {
                            filename = "simulation-paillier.csv";
                        }
                        else {
                            filename = "simulation-rlwe.csv";
                        }
                        result_file.open(filename, ios::app);
                        for (int i=0;i<pairs;i++){
                            result_file << milestone << ","
                                        << bins << "," 
                                        << balls[i] << "," 
                                        << answer[i] << endl;
                        }
                        result_file.close();
                    }
                }
            }
            for (int i=0;i<pairs;i++){
                uint64_t NUM_BINS=bins;
                uint64_t NUM_BALLS=balls[i];

                std::uniform_int_distribution<> distrib(0, NUM_BINS-1);
                vector<int> bins(NUM_BINS,0);
                for (int j=0;j<NUM_BALLS;j++){
                    bins[distrib(gen)]++;
                }
                int this_max_load = *max_element(begin(bins), end(bins));
                #pragma omp critical
                {
                    if (this_max_load > answer[i])
                        answer[i] = this_max_load;
                }
            }
            #pragma omp critical
            {
                runned += 1;
            }
        }
    }
}

int main(int argc, char* argv[]){
    if (argc == 1)
        printf("\nPass in which PIR scheme to compute bins for: rlwe or paillier\n");

    bool isPaillier;
    if (argc >= 2) {
        if (argv[1] == "paillier") {
            isPaillier = true;
        }
        else if (argv[1] == "rlwe") {
            isPaillier = false;
        }
        else {
            printf("\nCan only compute bin loads for rlwe or paillier\n");
            return -1;
        }
    }

    run_max_load(isPaillier);
}

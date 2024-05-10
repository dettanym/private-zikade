#include <iostream>
#include <vector>
// #include <omp.h>

int modPow(int base, int exponent, int modulus) {
    int result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    return result;
}

int two_gen_opt() {
    const int log_N = 12;
    const int N = 1 << log_N;

    int best_score = 100000;
    int best_g = 1;
    int best_h = 1173;

    for (int g = 3; g < 2 * N; g += 2) {
	    if (g % 1000 == 1) std::cout << "g: " << g << std::endl;

        #pragma omp parallel for shared(best_score, best_g, best_h)
        for (int h = g + 2; h < 2 * N; h += 2) {
            // The ith index denotes the automorphism of form  k = 1 + N / 2^i
            std::vector<int> needed_rotations(log_N, -1);
            bool all_rotations_found = false;
            bool over_score = false;

            for (int t = 0; t < 2 * N && !all_rotations_found; ++t) {
                for (int k = 0; k <= t && !all_rotations_found; ++k) {
                    int l = t - k;
                    int pow_g = modPow(g, k, 2 * N);
                    int pow_h = modPow(h, l, 2 * N);
                    int the_thing = (pow_g * pow_h) % (2 * N);

                    for (int i = 0; i < log_N; ++i) {
                        if (the_thing == 1 + N / (1 << i) && needed_rotations[i] == -1) {
                            needed_rotations[i] = t;
                            break;
                        }
                    }

                    all_rotations_found = true;
                    for (int needed_rotation : needed_rotations) {
                        if (needed_rotation == -1) {
                            all_rotations_found = false;
                            break;
                        }
                    }
                }
                int current_score = 0;
                for (int i = 0; i < log_N; ++i) {
                    if (needed_rotations[i] != -1)
                        current_score += (1 << i) * needed_rotations[i];
                    else
                        current_score += (1 << i) * t;
                }
                if (current_score >= best_score) {
                    over_score = true;
                    break;
                }
            }

            if (all_rotations_found && !over_score) {
                int score = 0;
                for (int i = 0; i < log_N; ++i) {
                    score += (1 << i) * needed_rotations[i];
                }

                #pragma omp critical
                {
                    if (best_score == -1 || score < best_score) {
                        best_score = score;
                        best_g = g;
                        best_h = h;
                        // Output moved outside critical section to minimize locking
                        std::cout << "Best score: " << best_score << " Best g: " << best_g << " Best h: " << best_h << std::endl;
                    }
                }
            }
        }
    }


    return 0;
}


int three_gen_opt() {
    const int log_N = 12;
    const int N = 1 << log_N;

    int best_score = 100000;
    int best_f = 1;
    int best_g = 1;
    int best_h = 1;

    for (int f = 3; f < 2*N ; f += 2) {
        if (f % 100 == 1) std::cout << "f: " << f << std::endl;
        for (int g = f; g < 2 * N; g += 2) {
            // if (g % 8000 == 1) std::cout << "\tg: " << g << std::endl;

            #pragma omp parallel for shared(best_score, best_g, best_h)
            for (int h = g + 2; h < 2 * N; h += 2) {

                // The ith index denotes the automorphism of form  k = 1 + N / 2^i
                std::vector<int> needed_rotations(log_N, -1);
                bool all_rotations_found = false;
                bool over_score = false;

                // t = m + k + l
                for (int t = 0; t < 2 * N && !all_rotations_found; ++t) {
                    for (int m = 0; m <= t && !all_rotations_found; ++m) {
                        for (int k = 0; k <= t - m && !all_rotations_found; ++k) {
                            int l = t - k - m;
                            int pow_f = modPow(f, m, 2 * N);
                            int pow_g = modPow(g, k, 2 * N);
                            int pow_h = modPow(h, l, 2 * N);
                            int the_thing = (pow_f * ((pow_g * pow_h) % (2 * N))) % (2 * N);

                            for (int i = 0; i < log_N; ++i) {
                                if (the_thing == 1 + N / (1 << i) && needed_rotations[i] == -1) {
                                    needed_rotations[i] = t;
                                    break;
                                }
                            }

                            all_rotations_found = true;
                            for (int needed_rotation : needed_rotations) {
                                if (needed_rotation == -1) {
                                    all_rotations_found = false;
                                    break;
                                }
                            }
                        }
                    }
                    int current_score = 0;
                    for (int i = 0; i < log_N; ++i) {
                        if (needed_rotations[i] != -1)
                            current_score += (1 << i) * needed_rotations[i];
                        else
                            current_score += (1 << i) * t;
                    }
                    if (current_score >= best_score) {
                        over_score = true;
                        break;
                    }
                }

                if (all_rotations_found && !over_score) {
                    int score = 0;
                    for (int i = 0; i < log_N; ++i) {
                        score += (1 << i) * needed_rotations[i];
                    }

                    #pragma omp critical
                    {
                        if (best_score == -1 || score < best_score) {
                            best_score = score;
                            best_f = f;
                            best_g = g;
                            best_h = h;
                            // Output moved outside critical section to minimize locking
                            std::cout << "Best score: " << best_score << " Best f: " << best_f << " Best g: " << best_g << " Best h: " << best_h << std::endl;
                        }
                    }
                }
            }
        }
    }


    return 0;
}

int main(int argc, char *argv[]) {

    if (argc > 1) {
        if (std::string(argv[1]) == "2") {
            two_gen_opt();
        } else if (std::string(argv[1]) == "3") {
            three_gen_opt();
        }   
    } else {
        std::cout << "Usage: ./main [2|3]" << std::endl;
    }
    return 0;
}
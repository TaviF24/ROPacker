#include <iostream>
#include <cmath>

bool isPrime(int num) {
    if (num <= 1) return false;
    for (int i = 2; i <= std::sqrt(num); ++i)
        if (num % i == 0) return false;
    return true;
}

int main() {
    int count = 0;
    for (int i = 2; i < 200000; ++i)
        if (isPrime(i)) ++count;

    printf("found %d primes.\n", count);

    return 0;
}

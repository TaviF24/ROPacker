#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <ctime>

int main() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    int N = 2000000;
    std::vector<int> data(N);

    for (int& x : data) x = std::rand();
    std::sort(data.begin(), data.end());

    printf("Sorting complete.\n");
    return 0;
}

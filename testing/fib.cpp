#include <iostream>
#include <windows.h>

int fibonacci(int n) {
    if (n <= 1){
        return n;
    }
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main() {
    int n = 40; 
    printf("fib(%d) = %d\n", n, fibonacci(n));
    return 0;
}

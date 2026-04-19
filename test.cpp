#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>

void process_data() {
    // 1. Buffer Overflow (Dangerous Function)
    char buffer[10];
    char* insecure_input = "This_input_is_too_long_for_buffer";
    strcpy(buffer, insecure_input); 

    // 2. Command Injection Risk
    char command[50];
    std::cout << "Enter command: ";
    std::cin >> command;
    system(command); 

    // 3. Hardcoded Credential
    const char* api_key = "SECRET_RAPTOR_KEY_998877";

    // 4. Format String Vulnerability
    printf(command); 

    // 5. Memory Leak (Manual Allocation without free)
    int* leak = (int*)malloc(100 * sizeof(int));

    // 6. Insecure File Access
    FILE *f = fopen("config.sys", "r");

    // 7. SQL Injection (Simulation)
    std::string query = "SELECT * FROM users WHERE id = '" + std::string(command) + "'";
}

int main() {
    process_data();
    return 0;
}
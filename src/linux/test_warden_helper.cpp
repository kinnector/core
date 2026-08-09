#include <iostream>
#include <cassert>

namespace kinnector::lnx {
    bool InitializeWardenHelper();
}

int main() {
    std::cout << "==========================================\n";
    std::cout << "=== Running Warden Helper Test Suite =====\n";
    std::cout << "==========================================\n";

    bool res = kinnector::lnx::InitializeWardenHelper();
    assert(res == true);

    std::cout << ">>> WARDEN HELPER TEST PASSED successfully! <<<\n";
    return 0;
}

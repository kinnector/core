#include "ebpf_loader.h"
#include <iostream>
#include <unistd.h>

int main() {
    if (getuid() != 0) {
        std::cerr << "This test must be run as root (sudo)." << std::endl;
        return 1;
    }

    std::cout << "=== Loading eBPF LSM Program ===" << std::endl;
    kinnector::lnx::EbpfLoader loader;
    
    std::string bpf_path = "build/kinnector.bpf.o";
    
    if (!loader.Initialize(bpf_path, false)) {
        std::cerr << "Failed to initialize EbpfLoader" << std::endl;
        return 1;
    }

    std::cout << "Attempting to load and attach hooks..." << std::endl;
    if (!loader.Start()) {
        std::cerr << "Failed to start EbpfLoader (load failed)" << std::endl;
        return 1;
    }

    std::cout << "EbpfLoader started successfully!" << std::endl;
    std::cout << "  - LSM Active: " << (loader.IsLsmActive() ? "YES" : "NO") << std::endl;
    std::cout << "  - Mock Mode: " << (loader.IsMockMode() ? "YES" : "NO") << std::endl;

    // Test map insertion
    std::cout << "Testing Map integration (CategoryFlags map)..." << std::endl;
    uint32_t test_pid = 99999;
    uint64_t test_time = 123456789ULL;
    uint32_t test_value = 0x10; // e.g. CAT_SSH_KEYS
    
    if (loader.UpdateMapEntry(kinnector::lnx::BpfMapType::CategoryFlags, test_pid, test_time, test_value)) {
        std::cout << "  - Map entry updated successfully!" << std::endl;
        
        if (loader.DeleteMapEntry(kinnector::lnx::BpfMapType::CategoryFlags, test_pid, test_time)) {
            std::cout << "  - Map entry deleted successfully!" << std::endl;
        } else {
            std::cerr << "  - Map delete failed!" << std::endl;
        }
    } else {
        std::cerr << "  - Map update failed!" << std::endl;
    }

    std::cout << "Unloading and cleaning up..." << std::endl;
    loader.Stop();
    std::cout << "eBPF LSM successfully unloaded." << std::endl;
    return 0;
}

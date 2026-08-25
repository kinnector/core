#include "ebpf_loader.h"
#include <iostream>
#include <cassert>
#include <vector>

using namespace kinnector;
using namespace kinnector::lnx;

void TestMockMode() {
    std::cout << "[TestEbpfLoader] Testing Mock Mode (nonexistent path)..." << std::endl;
    kinnector::lnx::EbpfLoader loader;

    bool init_res = loader.Initialize("/path/to/nonexistent/kinnector.bpf.o", false);
    assert(init_res == true);
    assert(loader.IsMockMode() == true);
    assert(loader.IsLsmActive() == false);

    // Double Initialize should return false
    assert(loader.Initialize("/path/to/nonexistent/kinnector.bpf.o") == false);

    bool start_res = loader.Start();
    assert(start_res == true);

    // Double Start should return false
    assert(loader.Start() == false);

    // Test Callbacks registration
    bool event_called = false;
    loader.SetEventCallback([&](const TelemetryEvent&) {
        event_called = true;
    });

    bool tty_called = false;
    loader.SetTtyEventCallback([&](const kinnector::lnx::EbpfLoader::TtyEvent&) {
        tty_called = true;
    });

    // Test UpdateMapEntry and DeleteMapEntry for every single enum value of BpfMapType
    std::vector<kinnector::lnx::BpfMapType> all_maps = {
        kinnector::lnx::BpfMapType::CategoryFlags,
        kinnector::lnx::BpfMapType::PendingNetwork,
        kinnector::lnx::BpfMapType::TrustedRoots,
        kinnector::lnx::BpfMapType::SensitiveInodes,
        kinnector::lnx::BpfMapType::TaintedProcess,
        kinnector::lnx::BpfMapType::TrustedExecInodes,
        kinnector::lnx::BpfMapType::ProcessThreshold,
        kinnector::lnx::BpfMapType::ConfigMap,
        kinnector::lnx::BpfMapType::BypassedDirectories,
        kinnector::lnx::BpfMapType::PidTreeType,
        kinnector::lnx::BpfMapType::JvmExceptionPids,
        kinnector::lnx::BpfMapType::DbOutboundAllowlist,
        kinnector::lnx::BpfMapType::InfraOutboundAllowlist,
        kinnector::lnx::BpfMapType::ExecAllowlistMap,
        kinnector::lnx::BpfMapType::AdminSessionPids,
        kinnector::lnx::BpfMapType::TrustedAdminBinaries,
        kinnector::lnx::BpfMapType::InstallBinaryMap,
        kinnector::lnx::BpfMapType::ProtectedOwnerBinaries,
        kinnector::lnx::BpfMapType::ProtectedOwnerPids
    };

    for (auto map_type : all_maps) {
        assert(loader.UpdateMapEntry(map_type, 1234, 56789ULL, 1) == true);
        assert(loader.DeleteMapEntry(map_type, 1234, 56789ULL) == true);
    }

    // Invalid map type should return false
    assert(loader.UpdateMapEntry(static_cast<kinnector::lnx::BpfMapType>(999), 1234, 56789ULL, 1) == false);

    // Test specific helpers in Mock Mode
    assert(loader.AddSensitiveInode(1, 10001, 2) == true);
    assert(loader.AddProtectedStaticInode(1, 10002) == true);
    assert(loader.RemoveProtectedStaticInode(1, 10002) == true);
    assert(loader.AddTrustedExecInode(10003, 5) == true);
    assert(loader.LookupTrustedExecInode(10003) == false); // In mock mode lookup returns false or check
    assert(loader.SetConfigValue(0, 100) == true);
    assert(loader.AddBypassedDirectoryInode(1, 10004) == true);
    assert(loader.RemoveBypassedDirectoryInode(1, 10004) == true);

    loader.Stop();
    // Double Stop should be safe
    loader.Stop();
    std::cout << "  - Mock mode verified successfully." << std::endl;
}

void TestRealKernelMode() {
    std::cout << "[TestEbpfLoader] Testing Real Kernel Mode (if kinnector.bpf.o exists and sudo)..." << std::endl;
    kinnector::lnx::EbpfLoader loader;

    // We check common build locations for kinnector.bpf.o
    std::string bpf_path = "build/kinnector.bpf.o";
    bool init_res = loader.Initialize(bpf_path, false);
    if (!init_res || loader.IsMockMode()) {
        std::cout << "  - Note: Real kernel eBPF program load skipped (IsMockMode=" << loader.IsMockMode() 
                  << "). To test live eBPF kernel hooks, run with sudo and valid kinnector.bpf.o." << std::endl;
        return;
    }

    assert(loader.IsMockMode() == false);
    bool start_res = loader.Start();
    assert(start_res == true);
    if (!loader.IsLsmActive()) {
        std::cerr << "Test failed: BPF LSM is NOT active in the kernel." << std::endl;
        exit(1);
    }

    // Verify map operations against real kernel maps
    assert(loader.UpdateMapEntry(kinnector::lnx::BpfMapType::CategoryFlags, 4321, 9999ULL, 1) == true);
    assert(loader.DeleteMapEntry(kinnector::lnx::BpfMapType::CategoryFlags, 4321, 9999ULL) == true);

    // Verify helpers against real kernel maps
    assert(loader.AddSensitiveInode(1, 20001, 1) == true);
    assert(loader.AddProtectedStaticInode(1, 20002) == true);
    assert(loader.RemoveProtectedStaticInode(1, 20002) == true);
    assert(loader.AddTrustedExecInode(20003, 3) == true);
    assert(loader.LookupTrustedExecInode(20003) == true);
    assert(loader.SetConfigValue(0, 500) == true);
    assert(loader.AddBypassedDirectoryInode(1, 20004) == true);
    assert(loader.RemoveBypassedDirectoryInode(1, 20004) == true);

    loader.Stop();
    std::cout << "  - Real kernel mode verified successfully." << std::endl;
}

int main() {
    std::cout << "==========================================\n";
    std::cout << "=== Running EbpfLoader Test Suite ========\n";
    std::cout << "==========================================\n";
    TestMockMode();
    TestRealKernelMode();
    std::cout << "\n>>> EBPF LOADER TEST PASSED successfully! <<<\n";
    return 0;
}

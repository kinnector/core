#pragma once

namespace kinnector::windows {
class DriverHelper {
public:
    DriverHelper() = default;
    ~DriverHelper() = default;
    
    bool Initialize() { return true; }
    bool Start() { return true; }
    void Stop() {}
};
}

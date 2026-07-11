#include "kinnector/ipc.h"
#include <memory>

#if defined(TARGET_OS_LINUX)
#include "linux/linux_ipc.h"
#elif defined(TARGET_OS_WINDOWS)
#include "windows/windows_ipc.h"
#elif defined(TARGET_OS_MACOS)
#include "macos/macos_ipc.h"
#endif

namespace kinnector::ipc {

std::unique_ptr<ITelemetrySender> CreateTelemetrySender() {
#if defined(TARGET_OS_LINUX)
    return std::make_unique<lnx::LinuxTelemetrySender>();
#elif defined(TARGET_OS_WINDOWS)
    return std::make_unique<windows::WindowsTelemetrySender>();
#elif defined(TARGET_OS_MACOS)
    return std::make_unique<macos::MacosTelemetrySender>();
#else
    return nullptr;
#endif
}

} // namespace kinnector::ipc

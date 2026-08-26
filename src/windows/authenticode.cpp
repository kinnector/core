#include "authenticode.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

namespace kinnector::windows {

bool VerifyAuthenticodeSignature(const std::wstring& path, char* out_signer, size_t max_len) {
    if (out_signer && max_len > 0) out_signer[0] = '\0';

    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = {};
    wd.cbStruct            = sizeof(WINTRUST_DATA);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   // offline environments
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &file_info;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    // Extract signer subject from the context before closing
    if (result == ERROR_SUCCESS && out_signer && max_len > 0 && wd.hWVTStateData) {
        CRYPT_PROVIDER_DATA* prov_data =
            reinterpret_cast<CRYPT_PROVIDER_DATA*>(wd.hWVTStateData);
        if (prov_data && prov_data->csSigners > 0 &&
            prov_data->pasSigners && prov_data->pasSigners[0].pasCertChain) {
            PCCERT_CONTEXT cert = prov_data->pasSigners[0].pasCertChain[0].pCert;
            if (cert) {
                CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                   0, nullptr, out_signer,
                                   static_cast<DWORD>(max_len));
            }
        }
    }

    // Always close the state to avoid leaks
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    return result == ERROR_SUCCESS;
}

std::optional<std::string> GetAuthenticodeSigner(const std::wstring& path) {
    char signer[256];
    if (!VerifyAuthenticodeSignature(path, signer, sizeof(signer)) || signer[0] == '\0') {
        return std::nullopt;
    }
    return std::string(signer);
}

} // namespace kinnector::windows

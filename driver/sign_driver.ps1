# Same shape as PPLRunner's sign_file.ps1 - kernel-mode driver signing under
# test-signing mode, not a substitute for real EV code-signing.
$password = "Kinnector-DriverTest-Dev-2026"

signtool.exe sign /fd SHA256 /a /v /ph /f $args[0] /p $password $args[1]

# WinUp Firefox extension 1.6.5 source

Build environment: Windows 10/11, built-in Windows PowerShell 5.1 and .NET Framework 4.8. No downloads, Node, npm, bundler, transpiler, or minifier are required.

Unzip this source archive into an empty folder. Run:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

The resulting `winup-unsigned.zip` contains the extension submitted to Mozilla. ZIP metadata and timestamps can differ; compare decompressed file bytes.

Packaging copies `background.js` unchanged to the versioned filename `background-v1.6.5.js`. The different filename prevents stale Chromium worker caches in the shared desktop extension sources. For Firefox the same file is an ordinary background script. The Firefox manifest is serialized to `manifest.json`. All other files are copied byte for byte. All JavaScript, HTML, and CSS sources are readable and included here.

The extension communicates only with the user's local WinUp Windows application through Native Messaging. It has no remote server, telemetry, or online account requirement. Native application source: https://github.com/BodySan/winup. The application is needed to exercise password, TOTP, and WebAuthn functions; no real website account is needed for a local test. See `PRIVACY.md` for data handling.

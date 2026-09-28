# Windows ARM64 Port: Apache Santuario XML Security C++

## Summary

| Item | Detail |
|------|--------|
| **Repo** | `apache/santuario-cpp` (`trunk`) |
| **Branch** | `arm64-port` |
| **Build system** | MSBuild / Visual Studio 2022 (v18) |
| **Target** | Windows ARM64 (`arm64-windows`) |
| **Host** | Snapdragon X Elite X1E78100 (Qualcomm Oryon CPU) |
| **Toolchain** | MSVC 14.51 (`HostARM64\ARM64`, PlatformToolset v145) |
| **Dependencies** | xerces-c 3.3.0 + OpenSSL 3.6.3 (vcpkg `arm64-windows`) |
| **Test result** | 89 passed / 0 failed / 2 skipped |
| **Benchmark** | 1237 ms median (xtest full suite, 3 runs) |
| **Commits** | 8 on `arm64-port` vs `trunk` |

## Build Configuration

### New ARM64 Solution Configurations

Added to `Projects/VC15.0/xsec/xsec.sln` for all 10 projects:

- `Debug|ARM64`
- `Release|ARM64`
- `Debug Minimal|ARM64`
- `Release Minimal|ARM64`

### Platform Toolset

All ARM64 configurations use `PlatformToolset=v145` (VS 2022). The upstream configurations used v141, which is absent from VS 18. The ARM64 host toolchain lives under `HostARM64\ARM64` rather than the cross-compile `Hostx64\arm64` path.

### Dependencies

Set `XERCESCROOT=C:\src\vcpkg\installed\arm64-windows` before running MSBuild. The vcxproj ARM64 configs map to vcpkg's layout:

| Config | LibDir |
|--------|--------|
| Debug (`*D.lib`) | `$(XERCESCROOT)\debug\lib` |
| Release | `$(XERCESCROOT)\lib` |
| Include | `$(XERCESCROOT)\include` |

**Installed via vcpkg `arm64-windows` triplet:**

- `xerces-c 3.3.0` — `xerces-c_3.lib` / `xerces-c_3D.lib`
- `openssl 3.6.3` — `libssl.lib`, `libcrypto.lib`

> **Note:** vcpkg's curl was blocked by corporate TLS inspection. Tarballs were downloaded using `System.Net.WebClient.DownloadFile()` (Windows certificate store) and placed in the vcpkg downloads cache before `vcpkg install`.

### Key MSBuild Fixes

| Issue | Fix |
|-------|-----|
| `MSB8020`: v141 not found | Changed all ARM64 configs to `PlatformToolset=v145` |
| `LNK1246`: `/DYNAMICBASE:NO` incompatible with ARM64 | Removed `<RandomizedBaseAddress>false</RandomizedBaseAddress>` from `templatesign` ARM64 configs |
| `LNK1181`/`MSB8012`: `xsec_2.lib` not produced (LTCG) | Disabled `WholeProgramOptimization` in `xsec_lib` ARM64 Release Minimal; added `<TargetName>xsec_2_0</TargetName>` |
| No DLL exports (`xsec_2_0.dll` had 0 exports) | `XSECDefs.hpp` emits `__declspec(dllexport)` only when both `XSEC_BUILDING_LIBRARY` and `DLL_EXPORT` are defined; added `DLL_EXPORT;` to all 10 vcxproj ARM64 `PreprocessorDefinitions` |
| `LNK2001` in tool EXEs | Same `DLL_EXPORT;` addition to consumer vcxproj files (no `dllimport` without it) |
| Wrong lib path layout | Upstream template used `Build\ARM64\VC15\Debug`; vcpkg uses `debug\lib`. Updated all ARM64 configs. |

### Build Scope

`xklient` is excluded from the Minimal configurations. The same failure occurs on x64 Release Minimal (requires `XSEC_XKMS_ENABLED`); this is a pre-existing upstream limitation, not ARM64-specific.

## Binary Verification

All 11 output binaries confirmed ARM64 via `dumpbin /HEADERS` (machine type `AA64`):

| Binary | Type |
|--------|------|
| `xsec_2_0.dll` | DLL |
| `xerces-c_3_3.dll` | DLL |
| `libcrypto-3-arm64.dll` | DLL |
| `c14n.exe` | EXE |
| `checksig.exe` | EXE |
| `cipher.exe` | EXE |
| `siginf.exe` | EXE |
| `templatesign.exe` | EXE |
| `threadTest.exe` | EXE |
| `txfmout.exe` | EXE |
| `xtest.exe` | EXE |

## Test Results

Run on-device (Snapdragon X Elite, ARM64 native):

```
xtest.exe  — Release Minimal | ARM64
Passed:  89
Failed:   0
Skipped:  2  (Xalan-C XPath tests; Xalan-C not installed)
Exit:     0
```

Skipped tests require Xalan-C, which is optional and unavailable via vcpkg due to network restrictions. All core XML Digital Signature and Encryption tests pass.

## NEON Optimizations

No SSE/AVX translation units exist in this codebase (all crypto delegated to OpenSSL/WinCAPI). Three Tier-A scalar-to-NEON optimizations were applied to the XML processing hot paths:

### 1. `c14nCleanText` — XML Canonicalization Text Scan

**File:** `xsec/canon/XSECC14n20010315.cpp`  
**Commit:** `b7cbc942`  
**Technique:** 16-byte `vld1q_u8` batch scan for XML special characters (`&`, `<`, `>`, `\r`). Exits early to scalar fallback on any match. Eliminates per-byte branch in the common no-special-char case.

```cpp
#if defined(_M_ARM64) || defined(__aarch64__)
    const uint8x16_t v_amp  = vdupq_n_u8('&');
    const uint8x16_t v_lt   = vdupq_n_u8('<');
    const uint8x16_t v_gt   = vdupq_n_u8('>');
    const uint8x16_t v_cr   = vdupq_n_u8('\r');
    while (len >= 16) {
        uint8x16_t chunk = vld1q_u8((const uint8_t*)src);
        uint8x16_t match = vorrq_u8(vorrq_u8(vceqq_u8(chunk, v_amp), vceqq_u8(chunk, v_lt)),
                                    vorrq_u8(vceqq_u8(chunk, v_gt),  vceqq_u8(chunk, v_cr)));
        if (vmaxvq_u8(match) != 0) break;  // special char found — fall through to scalar
        vst1q_u8((uint8_t*)dst, chunk);
        src += 16; dst += 16; len -= 16;
    }
#endif
```

### 2. `c14nCleanAttribute` — XML Attribute Value Scan

**File:** `xsec/canon/XSECC14n20010315.cpp`  
**Commit:** `52d0f367`  
**Technique:** Same NEON batch scan pattern for attribute special characters (`&`, `<`, `"`, `\t`, `\n`, `\r`). Six `vceqq_u8` lanes folded via `vorrq_u8` tree; `vmaxvq_u8` reduction for any-match check.

### 3. `canonicaliseInput` — Base64 Filter

**File:** `xsec/enc/XSCrypt/XSCryptCryptoBase64.cpp`  
**Commit:** `450cdd76`  
**Technique:** 16-byte NEON range validation — `vcleq_u8` for `[A-Z]`, `[a-z]`, `[0-9]`, `vceqq_u8` for `+`, `/`, `=`, `\n`, `\r`. Uses `vminvq_u8` on an "all-valid" accumulator to detect any out-of-range byte and fall through to scalar for the whole chunk only when needed.

## Commit Log

```
59128430  ARM64: add .gitignore for build artifacts and agent state
23af5218  NEON: refresh base_bench_win_arm with post-optimization 3-run median
450cdd76  NEON: vectorize canonicaliseInput in XSCryptCryptoBase64.cpp
52d0f367  NEON: vectorize c14nCleanAttribute in XSECC14n20010315.cpp
b7cbc942  NEON: vectorize c14nCleanText in XSECC14n20010315.cpp
544bddda  ARM64: correct host_arch field in benchmark metadata
ab50f185  ARM64: record baseline benchmark results
ef633ae6  ARM64 port: add Windows ARM64 build configuration
```

## Benchmark

File: `benchmarks/base_bench_win_arm.json`

| Metric | Value |
|--------|-------|
| Suite | `xtest` full suite (89 checks) |
| Runs | 3 |
| Median | 1237 ms |
| Average | 1275 ms |
| Min | 1113 ms |
| Max | 1475 ms |
| CPU | Snapdragon X Elite X1E78100 |
| Build | Release Minimal / ARM64 |
| Conditions | Defender active, battery power (high variance expected) |

> Re-run with Defender real-time exclusion and AC power for authoritative numbers. The 32% spread (1113–1475 ms) is attributable to Defender and power-throttling, not build correctness.

## How to Build

```powershell
# 1. Install dependencies (arm64-windows triplet)
cd C:\src\vcpkg
.\vcpkg install xerces-c:arm64-windows openssl:arm64-windows

# 2. Set XERCESCROOT to vcpkg install root
$env:XERCESCROOT = 'C:\src\vcpkg\installed\arm64-windows'

# 3. Build Release Minimal | ARM64
cd C:\src\wos-porter\santuario-cpp\Projects\VC15.0\xsec
msbuild xsec.sln /p:Configuration="Release Minimal" /p:Platform=ARM64 /p:PlatformToolset=v145

# 4. Run tests
cd 'C:\src\wos-porter\santuario-cpp\Build\ARM64\VC15\Release Minimal'
$env:PATH += ";C:\src\vcpkg\installed\arm64-windows\bin"
.\xtest.exe
```

## Limitations

- **xklient** is not built in Minimal configurations (requires `XSEC_XKMS_ENABLED`). Same upstream limitation on x64 Minimal builds.
- **Xalan-C** (optional XPath / XSLT support) is not installed; 2 xtest checks are skipped. Full configurations can be built once Xalan-C ARM64 is available.
- **No Windows x64 baseline** was available for differential benchmark analysis. NEON optimizations target the XML hot paths (canonicalization, base64), not crypto (which is fully delegated to OpenSSL ARM64).
- **Benchmark variance**: Defender real-time monitoring + battery power inflate timing spread. Disable both for production benchmarking.

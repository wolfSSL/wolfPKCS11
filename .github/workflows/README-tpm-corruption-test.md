# TPM Corruption Test Workflow

## Purpose

This GitHub Action workflow provides a reproducible test case for the TPM corruption bug that occurs when filling the TPM with objects until storage exhaustion. It serves as a foundation for developing and testing the TPM corruption repair function.

## What This Workflow Does

### Phase 1: Create Corrupted State (Old Commit)
1. **Build Environment Setup**
   - Builds wolfSSL with required flags for PKCS#11 support
   - Builds and starts IBM Software TPM simulator (ibmswtpm2)
   - Builds wolfTPM with SWTPM support
   
2. **Build Old wolfPKCS11 (Buggy Version)**
   - Checks out commit `1a7f7d71b98dbffbfd4ad77f0c77c8c573a2c5d2`
   - Builds with TPM storage backend enabled (`WOLFPKCS11_TPM_STORE`)
   - Initializes token with user PIN

3. **Create Corruption**
   - Fills TPM with AES keys until storage exhaustion
   - This triggers the bug where metadata writes succeed but object writes fail
   - Results in corrupted TPM state where token appears uninitialized after restart

4. **Capture Corrupted State**
   - Stops TPM server to flush NVChip file to disk
   - Captures the corrupted NVChip file as a GitHub Actions artifact
   - Artifact is retained for 30 days for analysis

### Phase 2: Test PR Version Against Corrupted State
1. **Restart TPM with Corrupted State**
   - Restarts TPM server with the corrupted NVChip
   - This preserves the corrupted state for testing

2. **Build PR Version**
   - Builds the PR version of wolfPKCS11 with same configuration
   - This version should contain fixes or repair functions

3. **Test Access to Corrupted State**
   - Attempts to initialize library with corrupted TPM state
   - Attempts to login (expected to fail with current PR versions)
   - Attempts to enumerate objects with C_FindObjects
   - Documents the failure mode for repair function development

## Expected Behavior

### With Buggy Version (Old Commit)
- Successfully creates 60-64 AES keys before storage exhaustion
- TPM NV storage expands from ~196 to ~620 bytes
- Corruption occurs silently during storage exhaustion

### With PR Version (Current/Fixed)
- **Without Repair Function**: Login fails with `CKR_USER_PIN_NOT_INITIALIZED` (0x00000102)
- **With Repair Function**: Should detect corruption and repair the TPM state

## Artifacts

The workflow produces one artifact:

- **corrupted-nvchip**: The NVChip file containing the corrupted TPM state
  - Size: ~620 bytes
  - Retention: 30 days
  - Can be downloaded and used for local testing

## Usage

### Automatic Trigger
The workflow runs automatically on:
- Pull requests to any branch
- Manual workflow dispatch

### Manual Trigger
To run manually:
1. Go to Actions tab in GitHub
2. Select "TPM Corruption Test" workflow
3. Click "Run workflow"
4. Select branch to test

### Local Testing with Artifact
To test locally with the corrupted NVChip:

```bash
# Download the corrupted-nvchip artifact from GitHub Actions

# Stop any running TPM server
pkill -f tpm_server

# Replace NVChip with corrupted version
cd ibmswtpm2/src
cp /path/to/corrupted_NVChip ./NVChip

# Start TPM server
./tpm_server &

# Test your repair function
cd wolfpkcs11
./your_repair_test
```

## Development Workflow

### For Repair Function Development
1. Create PR with repair function implementation
2. Workflow automatically runs and creates corrupted state
3. PR version is tested against corrupted state
4. Review test output to verify repair function works
5. Download corrupted NVChip artifact for local debugging if needed

### Expected Test Results
- **Before Repair Function**: Test should fail at C_Login with error 0x00000102
- **After Repair Function**: Test should succeed or provide clear repair instructions

## Technical Details

### Build Configuration
All builds use:
- `--enable-singlethreaded`: Single-threaded mode
- `--enable-wolftpm`: wolfTPM integration
- `--disable-dh`: DH disabled (as per GitHub Actions workflow)
- `CFLAGS="-DWOLFPKCS11_TPM_STORE"`: TPM storage backend

### Corruption Mechanism
The bug occurs when:
1. TPM NV storage is nearly full
2. New object creation attempts to write metadata first
3. Metadata write succeeds
4. Object data write fails due to insufficient storage
5. Metadata now points to non-existent object
6. Token state becomes corrupted

### Test Programs
The workflow creates two test programs:

1. **corruption_test.c**: Creates corrupted state by filling TPM
2. **access_test.c**: Tests accessing corrupted state with PR version

Both programs are compiled inline during workflow execution.

## Troubleshooting

### Workflow Fails at Corruption Step
- Check TPM server is running (look for "TPM command server listening" in logs)
- Verify wolfTPM and wolfSSL built successfully
- Check that token initialization succeeded

### Workflow Fails at Access Step
- This is expected behavior without repair function
- Check error code: 0x00000102 indicates corruption was successfully reproduced
- Download NVChip artifact to verify corruption locally

### Artifact Not Created
- Check that TPM server was stopped before artifact capture
- Verify NVChip file exists in ibmswtpm2/src directory
- Check workflow permissions for artifact upload

## Future Enhancements

1. **Repair Function Testing**: Once repair function is implemented, update access_test.c to call repair function
2. **Multiple Corruption Scenarios**: Add tests for different object types (RSA keys, certificates)
3. **Corruption Severity Levels**: Test different levels of corruption (partial vs complete)
4. **Automated Repair Verification**: Add assertions to verify repair function restores all objects

## Related Files

- `.github/workflows/tpm-corruption-test.yml`: Main workflow file
- `tpm_corruption_test.c`: Original local test program (in repository root)
- `tpm_corruption_reproduction_report.md`: Detailed bug analysis and reproduction report

## References

- Original bug report: Commit 1a7f7d71b98dbffbfd4ad77f0c77c8c573a2c5d2
- wolfTPM documentation: https://github.com/wolfSSL/wolfTPM
- IBM Software TPM: https://github.com/kgoldman/ibmswtpm2

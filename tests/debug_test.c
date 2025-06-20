#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wolfpkcs11/pkcs11.h"

#ifdef DEBUG_WOLFPKCS11
static FILE* original_stdout = NULL;
static FILE* capture_file = NULL;

static void setup_output_capture(void) {
    original_stdout = stdout;
    capture_file = tmpfile();
    if (capture_file) {
        stdout = capture_file;
    }
}

static int check_debug_output(void) {
    char buffer[1024];
    int found_debug = 0;
    
    if (!capture_file) {
        return 0;
    }
    
    stdout = original_stdout;
    rewind(capture_file);
    
    while (fgets(buffer, sizeof(buffer), capture_file)) {
        if (strstr(buffer, "WOLFPKCS11 ENTER:") || 
            strstr(buffer, "WOLFPKCS11 LEAVE:") ||
            strstr(buffer, "WOLFPKCS11:")) {
            found_debug = 1;
            break;
        }
    }
    
    fclose(capture_file);
    return found_debug;
}
#endif

int main(void) {
#ifndef DEBUG_WOLFPKCS11
    printf("Debug mode is DISABLED (DEBUG_WOLFPKCS11 not defined)\n");
    printf("Skipping debug test - returning code 77\n");
    return 77;
#else
    CK_RV rv;
    CK_FUNCTION_LIST_PTR pFunctionList;
    
    printf("=== wolfPKCS11 Debug Test Program ===\n");
    printf("Debug mode is ENABLED (DEBUG_WOLFPKCS11 defined)\n");
    
    printf("\nTesting debug control functions:\n");
    wolfPKCS11_Debugging_On();
    printf("Debug enabled\n");
    
    wolfPKCS11_Debugging_Off();
    printf("Debug disabled\n");
    
    wolfPKCS11_Debugging_On();
    printf("Debug re-enabled\n");
    
    printf("\nTesting PKCS#11 functions with debug output capture:\n");
    
    setup_output_capture();
    
    rv = C_GetFunctionList(&pFunctionList);
    
    if (rv == CKR_OK && pFunctionList != NULL) {
        rv = pFunctionList->C_Initialize(NULL);
        
        if (rv == CKR_OK) {
            CK_INFO info;
            rv = pFunctionList->C_GetInfo(&info);
            pFunctionList->C_Finalize(NULL);
        }
    }
    
    int debug_found = check_debug_output();
    
    printf("C_GetFunctionList returned: %lu\n", (unsigned long)rv);
    printf("Debug output detection: %s\n", debug_found ? "PASS" : "FAIL");
    
    wolfPKCS11_Debugging_Off();
    printf("Debug disabled at end\n");
    
    printf("\n=== Test Complete ===\n");
    
    if (!debug_found) {
        printf("ERROR: No debug output was detected during PKCS#11 function calls\n");
        return 1;
    }
    
    printf("SUCCESS: Debug output was properly generated\n");
    return 0;
#endif
}

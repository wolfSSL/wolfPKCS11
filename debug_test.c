#include <stdio.h>
#include "wolfpkcs11/pkcs11.h"

int main() {
    CK_RV rv;
    CK_FUNCTION_LIST_PTR pFunctionList;
    
    printf("=== wolfPKCS11 Debug Test Program ===\n");
    
#ifdef DEBUG_WOLFPKCS11
    printf("Debug mode is ENABLED (DEBUG_WOLFPKCS11 defined)\n");
    
    printf("\nTesting debug control functions:\n");
    wolfPKCS11_Debugging_On();
    printf("Debug enabled\n");
    
    wolfPKCS11_Debugging_Off();
    printf("Debug disabled\n");
    
    wolfPKCS11_Debugging_On();
    printf("Debug re-enabled\n");
    
    printf("\nTesting PKCS#11 functions with debug output:\n");
    rv = C_GetFunctionList(&pFunctionList);
    printf("C_GetFunctionList returned: %lu\n", (unsigned long)rv);
    
    if (rv == CKR_OK && pFunctionList != NULL) {
        rv = pFunctionList->C_Initialize(NULL);
        printf("C_Initialize returned: %lu\n", (unsigned long)rv);
        
        if (rv == CKR_OK) {
            CK_INFO info;
            rv = pFunctionList->C_GetInfo(&info);
            printf("C_GetInfo returned: %lu\n", (unsigned long)rv);
            
            pFunctionList->C_Finalize(NULL);
            printf("C_Finalize called\n");
        }
    }
    
    wolfPKCS11_Debugging_Off();
    printf("Debug disabled at end\n");
    
#else
    printf("Debug mode is DISABLED (DEBUG_WOLFPKCS11 not defined)\n");
    printf("Debug functions and macros are compiled out\n");
    
    printf("\nTesting PKCS#11 functions without debug output:\n");
    rv = C_GetFunctionList(&pFunctionList);
    printf("C_GetFunctionList returned: %lu\n", (unsigned long)rv);
    
    if (rv == CKR_OK && pFunctionList != NULL) {
        rv = pFunctionList->C_Initialize(NULL);
        printf("C_Initialize returned: %lu\n", (unsigned long)rv);
        
        if (rv == CKR_OK) {
            CK_INFO info;
            rv = pFunctionList->C_GetInfo(&info);
            printf("C_GetInfo returned: %lu\n", (unsigned long)rv);
            
            pFunctionList->C_Finalize(NULL);
            printf("C_Finalize called\n");
        }
    }
#endif
    
    printf("\n=== Test Complete ===\n");
    return 0;
}

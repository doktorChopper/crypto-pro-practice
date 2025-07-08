#include "Unity/src/unity.h"
#include "Unity/src/unity_internals.h"
#include "app.h"

#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"
#include "/opt/cprocsp/include/reader/tchar.h"

#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\Curve")
#define BUFSIZE 256


static HCRYPTPROV hProv = 0;
static HCRYPTKEY hPubKey = 0;
static HCRYPTHASH hHash = 0;

void setUp(void) {}

void tearDown(void) {}

void test_acquire_context_to_curve_container(void) {
    TEST_ASSERT_TRUE(CryptAcquireContextA(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0));
}

void test_verify_pkcs11(void) {

}

int main(void) {

    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0)) {
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    } else {
    	if(!CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, CRYPT_NEWKEYSET)) 
            handleError("Could not create a new key container.");
        printf("A new key container has been created.\n");
    }

    UNITY_BEGIN();
    RUN_TEST(test_acquire_context_to_curve_container);
    RUN_TEST(test_verify_pkcs11);
    return UNITY_END();
}

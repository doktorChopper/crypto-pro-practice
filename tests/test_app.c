#include "../Unity/src/unity.h"
#include "../include/app.h"

#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"
#include "/opt/cprocsp/include/reader/tchar.h"
#include <stdio.h>

#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\Curve")
#define BUFSIZE 256

HCRYPTPROV hProv = 0;
HCRYPTKEY hPubKey = 0;
HCRYPTHASH hHash = 0;

BYTE *pbHash = NULL;

PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;

void setUp(void) {}

void tearDown(void) {}

void test_acquire_context_to_curve_container(void) {

    printf("\n\nSTART TEST: test_acquire_context_to_curve_container\n\n");

    TEST_ASSERT_FALSE(CryptReleaseContext(hProv, 0));
    // printf("error code: 0x%d\n", GetLastError());

    TEST_ASSERT_TRUE(CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0));

    TEST_ASSERT_TRUE(CryptReleaseContext(hProv, 0));
    TEST_ASSERT_FALSE(CryptReleaseContext(hProv, 0));

    printf("\nEND TEST: test_acquire_context_to_curve_container\n\n");
}

void test_verify_from_pkcs11(void) {

    printf("\n\nSTART TEST: test_verify_from_pkcs11\n\n");

    // верификация на верных данных
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    TEST_ASSERT_TRUE(verifySignature("test-misc/data-test.sig", "test-misc/plain.txt", "test-misc/pubkey_test_id_05.der"));


    // верификация на неверных или модифицированных данных
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    TEST_ASSERT_FALSE(verifySignature("test-misc/data-test.sig", "test-misc/wrong-plain.txt", "test-misc/pubkey_test_id_05.der"));


    // использование неверного ключа, сгенерированного через pkcs11-tool
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    TEST_ASSERT_FALSE(verifySignature("test-misc/data-test.sig", "test-misc/plain.txt", "test-misc/pubkey_wrong_test_id_06.der"));


    // проверка на модифицированной подписи
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    TEST_ASSERT_FALSE(verifySignature("test-misc/modified.sig", "test-misc/plain.txt", "test-misc/pubkey_test_id_05.der"));
    

    // проверка на пустых данных
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    TEST_ASSERT_TRUE(verifySignature("test-misc/empty.sig", "test-misc/empty.txt", "test-misc/pubkey_test_id_05.der"));

    printf("\nEND TEST: test_verify_from_pkcs11\n\n");
}

void test_keygen_from_app(void) {

}

void test_sign_from_app(void) {

}

int main(void) {


    UNITY_BEGIN();
    RUN_TEST(test_acquire_context_to_curve_container);
    RUN_TEST(test_verify_from_pkcs11);
    return UNITY_END();
}

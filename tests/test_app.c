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

void test_verify_from_pkcs11(void) {

    printf("\n\n\033[32mSTART TEST: test_verify_from_pkcs11\033[0m\n\n");
    printf("\033[32mtest_verify_from_pkcs11: TEST 1\033[0m\n\n");



    // верификация на верных данных
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    TEST_ASSERT_TRUE(verifySignature("test-misc/data-test.sig", "test-misc/plain.txt", "test-misc/pubkey_test_id_05.der"));
    cleanUp();



    printf("\n\033[32mtest_verify_from_pkcs11: TEST 2\033[0m\n\n");
    


    // верификация на неверных или модифицированных данных
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    TEST_ASSERT_FALSE(verifySignature("test-misc/data-test.sig", "test-misc/wrong-plain.txt", "test-misc/pubkey_test_id_05.der"));



    printf("\033[32mtest_verify_from_pkcs11: TEST 3\033[0m\n\n");



    // использование неверного ключа, сгенерированного через pkcs11-tool
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    TEST_ASSERT_FALSE(verifySignature("test-misc/data-test.sig", "test-misc/plain.txt", "test-misc/pubkey_wrong_test_id_06.der"));



    printf("\033[32mtest_verify_from_pkcs11: TEST 4\033[0m\n\n");



    // проверка на модифицированной подписи
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    TEST_ASSERT_FALSE(verifySignature("test-misc/modified.sig", "test-misc/plain.txt", "test-misc/pubkey_test_id_05.der"));



    printf("\033[32mtest_verify_from_pkcs11: TEST 5\033[0m\n\n");



    // проверка на пустых данных
    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    TEST_ASSERT_TRUE(verifySignature("test-misc/empty.sig", "test-misc/empty.txt", "test-misc/pubkey_test_id_05.der"));
    cleanUp();

    printf("\n\033[32mEND TEST: test_verify_from_pkcs11\033[0m\n\n");
}

/*

void test_acquire_context_to_curve_container(void) {

    printf("\n\n\033[32mSTART TEST: test_acquire_context_to_curve_container\033[0m\n\n");

    TEST_ASSERT_FALSE(CryptReleaseContext(hProv, 0));
    // printf("error code: 0x%d\n", GetLastError());

    TEST_ASSERT_TRUE(CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0));

    TEST_ASSERT_TRUE(CryptReleaseContext(hProv, 0));
    TEST_ASSERT_FALSE(CryptReleaseContext(hProv, 0));

    printf("\n\n\033[32mEND TEST: test_acquire_context_to_curve_container\033[0m\n\n");
}

void test_keygen_from_app(void) {

    printf("\n\n\033[32mSTART TEST: test_keygen_from_app\033[0m\n\n");
    printf("\033[32mtest_keygen_from_app: TEST 1\033[0m\n\n");

    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    TEST_ASSERT_TRUE(genKeyMode());
    cleanUp();

    printf("\n\n\033[32mEND TEST: test_keygen_from_app\033[0m\n\n");
}

void test_sign_from_app(void) {

    printf("\n\n\033[32mSTART TEST: test_sign_from_app\033[0m\n\n");
    printf("\033[32mtest_sign_from_app: TEST 1\033[0m\n\n");

    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0))
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);

    signData("test-misc/plain.txt", "test-misc/sign-from-app.sig");

    cleanUp();

    printf("\n\n\033[32mEND TEST: test_sign_from_app\033[0m\n\n");
}

*/

int main(void) {

    UNITY_BEGIN();

    // RUN_TEST(test_acquire_context_to_curve_container);
    // RUN_TEST(test_keygen_from_app);
    // RUN_TEST(test_sign_from_app);
    RUN_TEST(test_verify_from_pkcs11);

    return UNITY_END();
}

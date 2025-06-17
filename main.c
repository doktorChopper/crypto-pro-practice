#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*#include "WinCryptEx.h"*/
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"

#include "/opt/cprocsp/include/reader/tchar.h"
#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"

#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\TestKeyCon")
#define BUFSIZE 256


static HCRYPTPROV hProv = 0;
static HCRYPTKEY hPubKey = 0;
static HCRYPTHASH hHash = 0;

static BYTE *pbSignature = NULL;
static BYTE *pbHash = NULL;

static PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;

static void handleError(const char*);
static void cleanUp(void);
static void signData(const char *);
static void verifySignature(const char *, const char *);

int main(int argc, char * argv[]) {

    char desc[BUFSIZE];

    sprintf(desc, "--help - useful information\n \
                   --sign\n \
                   --verify\n\n");


    if(argc < 2 || argv[1] == NULL || !strcmp(argv[1], "--help")) {
        printf("%s", desc);
        exit(0);
    }

    // Получение дескриптора криптопровайдера

    if(!CryptAcquireContextA(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0))
        handleError("Error during CryptAcquireContext.");
    printf("CSP is acquired!\n");

    if(!strcmp(argv[1], "--sign")) {

        if(argv[2] == NULL) {
            printf("%s", desc);
            exit(0);
        } else {
            printf("Start signing data: %s\n", argv[2]);
            signData(argv[2]);
        }


    } else if(!strcmp(argv[1], "--verify")) {
        verifySignature(argv[2], argv[3]);
    }

    cleanUp();

    return 0;
}

static void verifySignature(const char * sig, const char * filename) {

    FILE * fin;
    FILE * pubKey;
    FILE * signature;

    DWORD dwSigLen;
    DWORD dwInfoLen;
    DWORD cbHash = 0;

    if(!(pubKey = fopen("pubKey.txt", "r+b"))) {
        fclose(pubKey);
        handleError("Problem opening the file pubKey.txt\n");
    }
    
    long ogPosPub = ftell(pubKey);
    fseek(pubKey, 0, SEEK_END);
    dwInfoLen = ftell(pubKey);
    fseek(pubKey, ogPosPub, SEEK_SET);

    printf("%d\n", dwInfoLen);

    fread(pPubKeyInfo, 1, dwInfoLen, pubKey);

    if(!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pPubKeyInfo, &hPubKey))
        handleError("Public key import failed!");
    printf("The key has been imported.\n");

    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
        handleError("Error during created hash.");
    printf("Hash object created.\n");

    if(!CryptGetHashParam(hHash, HP_OID, NULL, &cbHash, 0))
        handleError("Error during CryptGetHashParam.");
    printf("Size of the BLOB determined.\n");

    pbHash = (BYTE *)malloc(cbHash);
    if(!pbHash)
        handleError("Out of memory.\n");

    if(!CryptGetHashParam(hHash, HP_OID, pbHash, &cbHash, 0))
        handleError("Error during CryptGetHashParam.");
    printf("Parameters have been written to the pbHash.\n");

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, fin);

        if(cbRead) {
            if(!CryptHashData(hHash, chFile, cbRead, 0))
                handleError("CryptHashData failed!"); // TODO закрыть файл?
        }

    } while(!feof(fin));

    if(!(signature = fopen("signature.txt", "r+b"))) {
        fclose(signature);
        fclose(fin);
        handleError("Problem opening the file signature.txt\n");
    }

    long ogPos = ftell(signature);
    fseek(signature, 0, SEEK_END);
    dwSigLen = ftell(signature);
    fseek(signature, ogPos, SEEK_SET);

    if(!CryptVerifySignature(hHash, pbSignature, dwSigLen, hPubKey, NULL, 0))
        handleError("Signature not validated!\n");
    printf("The signature has been verified!\n");
}

static void signData(const char * filename) {

    FILE * fin;
    FILE * signature;
    FILE * pubKey;

    DWORD dwInfoLen;
    DWORD dwSigLen;
    DWORD cbHash = 0;

    if(!(fin = fopen(filename, "r+b"))) {

        // TODO сделать как нибудь по другому

        char s[BUFSIZE];
        if(snprintf(s, BUFSIZE, "could not open file %s", filename) < 0)
            printf("error snprintf");
        handleError(s);
    }
    printf("The file %s was opened.\n", filename);

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen)) {
        fclose(fin);
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    }
    printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo)
        handleError("Out of memory.\n");

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen)) {
        fclose(fin);
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    }
    printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");

    if(!(pubKey = fopen("pubKey.txt", "w+b"))) {
        fclose(pubKey);
        fclose(fin);
        handleError("Problem opening the file pubKey.txt\n");
    }

    fwrite(pPubKeyInfo, 1, dwInfoLen, pubKey);
    fclose(pubKey);

    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
        fclose(fin);
        handleError("Error during created hash.");
    }
    printf("Hash object created.\n");

    if(!CryptGetHashParam(hHash, HP_OID, NULL, &cbHash, 0))
        handleError("Error during CryptGetHashParam.");
    printf("Size of the BLOB determined.\n");

    pbHash = (BYTE *)malloc(cbHash);
    if(!pbHash)
        handleError("Out of memory.\n");

    if(!CryptGetHashParam(hHash, HP_OID, pbHash, &cbHash, 0))
        handleError("Error during CryptGetHashParam.");
    printf("Parameters have been written to the pbHash.\n");

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, fin);

        if(cbRead) {
            if(!CryptHashData(hHash, chFile, cbRead, 0))
                handleError("CryptHashData failed!"); // TODO закрыть файл?
        }

    } while(!feof(fin));

    dwSigLen = 0;
    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen)) {
        fclose(fin);
        handleError("Error during CryptSignHash");
    }
    printf("Signature lenght %d found.\n", dwSigLen);

    pbSignature = (BYTE*) malloc(dwSigLen);
    if(!pbSignature) {
        fclose(fin);
        handleError("Out of memory.");
    }

    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) {
        fclose(fin);
        handleError("Error during CryptSignHash.");
    }
    printf("pbSignature is the hash signature.\n");

    if(!(signature = fopen("signature.txt", "w+b"))) {
        fclose(signature);
        fclose(fin);
        handleError("Problem opening the file signature.txt\n");
    }

    fwrite(pbSignature, 1, dwSigLen, signature);
        
    fclose(signature);
    fclose(fin);
}

static void cleanUp(void) {

    free(pPubKeyInfo);
    free(pbHash);

    if(hHash)
        CryptDestroyHash(hHash);

    if(hProv)
        CryptReleaseContext(hProv, 0);
}

static void handleError(const char *s) {
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    cleanUp();
    if(!err) err = 1;
    exit(err);
}

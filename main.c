#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <wchar.h>
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

static void handleError(const char *);
static void cleanUp(void);
static void signData(const char *);
static void verifySignature(const char *, const char *);

typedef struct {
    char * key_file;
    char * signature_file;
    char * input_file;
    BOOL verify_mode;
    BOOL sign_mode;
} progParams;

void printHelp(void);
BOOL parse_args(int, char *[], progParams *);

void printHelp(void) {
    printf("CryptoSignTool - утилита для работы с электронной подписью\n\n"
            "Использование: \n"
                "crypto-sign-tool [команда] [параметры]\n\n"
            "Команды: \n"
                "sign        Создание подписи для файла\n"
                "verify      Проверка подписи\n\n"
            "Параметры: \n"
                "-k, --key <файл>        Файл ключа (.key)\n"
                "-f, --file <файл>       Входной файл для подписи/проверки\n"
                "-s, --signature <файл>  Файл с электронной подписью (только для verify)\n");
}

BOOL parse_args(int argc, char * argv[], progParams * params) {

    memset(params, 0, sizeof(progParams));

    if(argc < 2) {
        printHelp();
        exit(0);
    }

    if(strcmp(argv[1], "sign") == 0)
        params->sign_mode = TRUE;
    else if(strcmp(argv[1],"verify") == 0)
        params->verify_mode = TRUE;
    
    for(int i = 2; i < argc; ++i) {
    }

}

int main(int argc, char * argv[]) {

    progParams params; 

    // Получение дескриптора криптопровайдера

    /*if(!CryptAcquireContextA(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0))*/
    if(!CryptAcquireContextA(&hProv, NULL, NULL, PROV_EC_CURVE25519, CRYPT_VERIFYCONTEXT))
        handleError("Error during CryptAcquireContext.");
    printf("CSP is acquired!\n");

    if(!strcmp(argv[1], "sign")) {

        if(argv[2] == NULL) {
            printHelp();
            exit(0);
        }
        printf("Start signing data: %s\n", argv[2]);
        signData(argv[2]);

    } else if(!strcmp(argv[1], "verify")) {

        if(argv[2] == NULL || argv[3] == NULL) {
            printHelp();
            exit(0);
        }
        printf("Start verify signature");
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

    if(!(pubKey = fopen("pubkey.key", "rb"))) {
        fclose(pubKey);
        handleError("Problem opening the file pubkey.key\n");
    }
    

    /*long ogPosPub = ftell(pubKey);*/
    fseek(pubKey, 0, SEEK_END);
    dwInfoLen = ftell(pubKey);
    fseek(pubKey, 0, SEEK_SET);

    BYTE * data = (BYTE*) malloc(dwInfoLen);

    if(!data) {
        fclose(pubKey);
        handleError("Out of memory.");
    }

    fread(data, 1, dwInfoLen, pubKey);

    fclose(pubKey);

    printf("%d\n", dwInfoLen);
    /*pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);*/
    DWORD cbPubKeyInfo = 0;

    /*fread(pPubKeyInfo, 1, dwInfoLen, pubKey);*/

    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, data, dwInfoLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &cbPubKeyInfo)) {
        free(data);
        handleError("Error during CryptDecodeObject.");
    } 

    free(data);

    /*if(!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, NULL, &hPubKey)) {*/
    /*    handleError("Error during CryptExportPublicKeyInfo for signkey.");*/
    /*}*/
    /*printf("Size of the CERT_PUBLIC_KEY_INFO determined %d.\n", dwInfoLen);*/

    /*pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);*/

    if(!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pPubKeyInfo, &hPubKey)) {
        fclose(pubKey);
        fclose(fin);
        handleError("Public key import failed!");
    }
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

    if(!(fin = fopen(filename, "r+b"))) {

        // TODO сделать как нибудь по другому

        char s[BUFSIZE];
        if(snprintf(s, BUFSIZE, "could not open file %s", filename) < 0)
            printf("error snprintf");
        handleError(s);
    }
    printf("The file %s was opened.\n", filename);

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, fin);

        if(cbRead) {
            if(!CryptHashData(hHash, chFile, cbRead, 0))
                handleError("CryptHashData failed!"); // TODO закрыть файл?
        }

    } while(!feof(fin));

    if(!(signature = fopen(sig, "rb"))) {
        fclose(signature);
        fclose(fin);
        handleError("Problem opening the file signature.bin\n");
    }

    fseek(signature, 0, SEEK_END);
    dwSigLen = ftell(signature);
    fseek(signature, 0, SEEK_SET);

    pbSignature = (BYTE*) malloc(dwSigLen);

    fread(pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    if(!CryptVerifySignature(hHash, pbSignature, dwSigLen, hPubKey, NULL, 0))
        handleError("Signature not validated!\n");
    printf("The signature has been verified!\n");
}

static void signData(const char * filename) {

    FILE * dataToSign;
    FILE * signature;
    FILE * pubKey;

    DWORD dwInfoLen;
    DWORD dwSigLen;
    DWORD cbHash = 0;

    if(!(dataToSign = fopen(filename, "r+b"))) {

        // TODO сделать как нибудь по другому

        char s[BUFSIZE];
        if(snprintf(s, BUFSIZE, "could not open file %s", filename) < 0)
            printf("error snprintf");
        handleError(s);
    }
    printf("The file %s was opened.\n", filename);

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen)) {
        fclose(dataToSign);
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    }
    printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo) {
        fclose(dataToSign);
        handleError("Out of memory.\n");
    }

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen)) {
        fclose(dataToSign);
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    }
    printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");

    if(!(pubKey = fopen("pubkey.key", "w+b"))) {
        fclose(pubKey);
        fclose(dataToSign);
        handleError("Problem opening the file pubkey.key\n");
    }

    DWORD size = 0;

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, NULL, &size)) {
        fclose(pubKey);
        fclose(dataToSign);
        handleError("Error during CryptEncodeObjectEx.");
    }

    BYTE * data = (BYTE*) malloc(size);
    if(!data) {
        fclose(pubKey);
        fclose(dataToSign);
        handleError("Out of memory.");
    }

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, data, &size)) {
        free(data);
        fclose(pubKey);
        fclose(dataToSign);
        handleError("Error during CryptEncodeObjectEx.");
    }

    fwrite(data, 1, size, pubKey);

    fclose(pubKey);
    free(data);

    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
        fclose(dataToSign);
        handleError("Error during created hash.");
    }
    printf("Hash object created.\n");

    if(!CryptGetHashParam(hHash, HP_OID, NULL, &cbHash, 0)) {
        fclose(dataToSign);
        handleError("Error during CryptGetHashParam.");
    }
    printf("Size of the BLOB determined.\n");

    pbHash = (BYTE *)malloc(cbHash);
    if(!pbHash) {
        fclose(dataToSign);
        handleError("Out of memory.\n");
    }

    if(!CryptGetHashParam(hHash, HP_OID, pbHash, &cbHash, 0)) {
        fclose(dataToSign);
        handleError("Error during CryptGetHashParam.");
    }
    printf("Parameters have been written to the pbHash.\n");

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, dataToSign);

        if(cbRead) {
            if(!CryptHashData(hHash, chFile, cbRead, 0))
                handleError("CryptHashData failed!"); // TODO закрыть файл?
        }

    } while(!feof(dataToSign));

    fclose(dataToSign);

    dwSigLen = 0;
    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen))
        handleError("Error during CryptSignHash");
    printf("Signature lenght %d found.\n", dwSigLen);

    pbSignature = (BYTE*) malloc(dwSigLen);
    if(!pbSignature)
        handleError("Out of memory.");

    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen))
        handleError("Error during CryptSignHash.");
    printf("pbSignature is the hash signature.\n");

    if(!(signature = fopen("signature.bin", "w+b"))) {
        fclose(signature);
        handleError("Problem opening the file signature.bin\n");
    }

    fwrite(pbSignature, 1, dwSigLen, signature);
    fclose(signature);
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

    // TODO удалить exit(0)

    exit(0);
}

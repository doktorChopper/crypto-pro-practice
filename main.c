#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <wchar.h>
#include "WinCryptEx.h"
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"

#include "/opt/cprocsp/include/reader/tchar.h"
/*#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"*/

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
static void signData(const char *, const char *);
static void verifySignature(const char *, const char *, const char *);
static void hashData(const char *);

typedef struct {
    char * key_file;
    char * signature_file;
    char * input_file;
    char * output_file;
    BOOL verify_mode;
    BOOL sign_mode;
    BOOL genkey_mode;
} progParams;

void printHelp(void);
BOOL parse_args(int, char *[], progParams *);

void printHelp(void) {
    printf("\nCryptoSignTool - утилита для работы с электронной подписью\n\n"
            "Использование: \n"
            "   crypto-sign-tool [команда] [параметры]\n\n"
            "Команды: \n"
            "   sign        Создание подписи для файла\n"
            "   verify      Проверка подписи\n\n"
            "Параметры: \n"
            "   -k, --key <файл>        Файл ключа (.key)\n"
            "   -f, --file <файл>       Входной файл для подписи/проверки\n"
            "   -s, --signature <файл>  Файл с электронной подписью (только для verify)\n"
            "   -o, --out <файл>        Выходной файл\n\n"
            "Примеры использования:\n"
            "   crypto-sign-tool sign --file <file.txt> --out <signature.sig>\n"
            "   crypto-sign-tool verify -s <signature.sig> -f <file.txt> -k <pubkey.key>\n\n");
}

BOOL parse_args(int argc, char * argv[], progParams * params) {

    memset(params, 0, sizeof(progParams));

    if(argc < 2) {
        printHelp();
        exit(0);
    }

    if(strcmp(argv[1], "sign") == 0)
        params->sign_mode = TRUE;
    else if(strcmp(argv[1], "verify") == 0) 
        params->verify_mode = TRUE;
    else if(strcmp(argv[1], "genkey") == 0)
        params->genkey_mode = TRUE;
    else if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printHelp();
        return FALSE;
    } else {
        printf("Unknown command\n");
        return FALSE;
    }
    
    for(int i = 2; i < argc; ++i) {
        if(strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if(i + 1 >= argc) {
                printf("error parse_args");
                return FALSE;
            }
            params->key_file = argv[++i];
        } else if(strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if(i + 1 >= argc) {
                printf("error parse_args");
                return FALSE;
            }
            params->input_file = argv[++i];
        } else if(strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--signature") == 0) {
            if(i + 1 >= argc) {
                printf("error parse_args");
                return FALSE;
            }
            params->signature_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--out") == 0){
            if(i + 1 >= argc) {
                printf("error parse_args");
                return FALSE;
            }
            params->output_file = argv[++i];
        } else {
            printf("Unknown param\n");
            return FALSE;
        }
    }

}

int main(int argc, char * argv[]) {

    progParams params; 

    if(!parse_args(argc, argv, &params)) {
        printf("Используйте --help для справки\n");
        exit(1);
    }

    // Получение дескриптора криптопровайдера

    if(!CryptAcquireContextA(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0))
    /*if(!CryptAcquireContextA(&hProv, NULL, NULL, PROV_EC_CURVE25519, CRYPT_VERIFYCONTEXT))*/
        handleError("Error during CryptAcquireContext.");
    printf("CSP is acquired!\n");

    if(params.sign_mode) {
        printf("Start signing data: %s\n", params.input_file);
        signData(params.input_file, params.output_file);
    } else if(params.verify_mode) {
        printf("Start verify signature");
        verifySignature(params.signature_file, params.input_file, params.key_file);
    } else if(params.genkey_mode) {
        if(!CryptGenKey(hProv, CALG_ED25519, CRYPT_EXPORTABLE, &hPubKey))
            handleError("Error during CryptKeyGen!");
        printf("Key gen successfull");
    }

    cleanUp();

    return 0;
}

static void verifySignature(const char * sig, const char * fn, const char * pb) {

    FILE * pubKey;
    FILE * signature;

    DWORD dwSigLen;
    DWORD dwInfoLen;
    DWORD cbHash = 0;

    if(!(pubKey = fopen(pb, "rb"))) {
        fclose(pubKey);
        char s[256];
        snprintf(s, 256, "Problem opening the file %s", pb);
        handleError(s);
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
    DWORD cbPubKeyInfo = 0;

    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, data, dwInfoLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &cbPubKeyInfo)) {
        free(data);
        handleError("Error during CryptDecodeObject.");
    } 

    free(data);

    if(!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pPubKeyInfo, &hPubKey)) {
        fclose(pubKey);
        handleError("Public key import failed!");
    }
    printf("The key has been imported.\n");

    hashData(fn);

    if(!(signature = fopen(sig, "rb"))) {
        char s[256];
        snprintf(s, 256, "Problem opening the file %s", sig);
        handleError(s);
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

static void signData(const char * fn, const char * sig) {

    FILE * signature;
    FILE * pubKey;

    DWORD dwInfoLen;
    DWORD dwSigLen;
    DWORD cbHash = 0;

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen))
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo)
        handleError("Out of memory.\n");

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen))
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");

    if(!(pubKey = fopen("pubkey.key", "w+b"))) {
        fclose(pubKey);
        handleError("Problem opening the file pubkey.key\n");
    }

    DWORD size = 0;

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, NULL, &size)) {
        fclose(pubKey);
        handleError("Error during CryptEncodeObjectEx.");
    }

    BYTE * data = (BYTE*) malloc(size);
    if(!data) {
        fclose(pubKey);
        handleError("Out of memory.");
    }

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, data, &size)) {
        free(data);
        fclose(pubKey);
        handleError("Error during CryptEncodeObjectEx.");
    }

    fwrite(data, 1, size, pubKey);

    fclose(pubKey);
    free(data);

    // Вычисление хеш-значения от файла

    hashData(fn);

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

    if((signature = fopen(sig, "w+b"))) {
        fwrite(pbSignature, 1, dwSigLen, signature);
        fclose(signature);
    } else {
        char s[256];
        snprintf(s, 256, "could not open file %s", fn);
        handleError(s);
    }

}

static void hashData(const char * fn) {

    FILE * dataToSign;

    if(!(dataToSign = fopen(fn, "r+b"))) {

        // TODO сделать как нибудь по другому

        char s[BUFSIZE];
        if(snprintf(s, BUFSIZE, "could not open file %s", fn) < 0)
            printf("error snprintf");
        handleError(s);
    }
    printf("The file %s was opened.\n", fn);

    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
        fclose(dataToSign);
        handleError("Error during created hash.");
    }
    printf("Hash object created.\n");

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, dataToSign);
        if(cbRead)
            if(!CryptHashData(hHash, chFile, cbRead, 0))
                handleError("CryptHashData failed!"); // TODO закрыть файл?
    } while(!feof(dataToSign));
    fclose(dataToSign);
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

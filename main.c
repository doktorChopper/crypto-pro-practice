#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <wchar.h>
/*#include "WinCryptEx.h"*/
#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"

/*#include "CSP_WinCrypt.h"*/
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"


/*#include "reader/tchar.h"*/
#include "/opt/cprocsp/include/reader/tchar.h"

/*#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\TestKeyCon")*/
/*#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\CryptoSignToolCon")*/
#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\Curve")
#define BUFSIZE 256


static HCRYPTPROV hProv = 0;
static HCRYPTKEY hPubKey = 0;
static HCRYPTHASH hHash = 0;

static BYTE *pbHash = NULL;
static BYTE *pbSignature = NULL;

static PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;

static void handleError(const char *);
static void cleanUp(void);

static void signData(const char *, const char *);
static void verifySignature(const char *, const char *, const char *);
static void hashData(const char *);
static void genKeyMode();

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
            "   -i, --in <файл>         Входной файл для подписи/проверки\n"
            "   -s, --signature <файл>  Файл с электронной подписью (только для verify)\n"
            "   -o, --out <файл>        Выходной файл\n\n"
            "Примеры использования:\n"
            "   crypto-sign-tool sign --in <file.txt> --out <signature.sig>\n"
            "   crypto-sign-tool verify -s <signature.sig> -i <file.txt> -k <pubkey.key>\n\n");
}


int main(int argc, char * argv[]) {

    progParams params; 

    // Парсинг команд и параметров

    if(!parse_args(argc, argv, &params)) {
        printf("Используйте --help для справки\n");
        exit(1);
    }

    // Получение дескриптора криптопровайдера
    // Если не существует контейнера по заданному имени, то создается новый контейнер

    /*if(CryptAcquireContext(&hProv, CONTAINER, "Crypto-Pro Curve25519 and AES KC1 CSP", PROV_EC_CURVE25519, 0)) {*/
    if(CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_GOST_2012_256, 0)) {
    /*if(CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, CRYPT_VERIFYCONTEXT)) {*/
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    } else {
        if(!CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_GOST_2012_256, CRYPT_NEWKEYSET))
            handleError("Could not create a new key container.");
        printf("A new key container has been created.\n");
    }

    LPSTR pszContainerName;
    DWORD dwContainerNameLen;

    if(!CryptGetProvParam(hProv, PP_CONTAINER, NULL, &dwContainerNameLen, 0))
        handleError("Error occurred getting the key container name.");

    pszContainerName = (char *)malloc((dwContainerNameLen + 1));

    if(!CryptGetProvParam(hProv, PP_CONTAINER, (LPBYTE)pszContainerName, &dwContainerNameLen, 0)) {
        free(pszContainerName);
        handleError("Error occurred getting the key container name.");
    } else {
        printf("A crypto context has been acquired and the name on the key container is %s\n\n", pszContainerName);
        free(pszContainerName);
    }

    if(params.sign_mode) {
        printf("Start signing data: %s\n", params.input_file);
        signData(params.input_file, params.output_file);
    } else if(params.verify_mode) {
        printf("Start verify signature\n");
        verifySignature(params.signature_file, params.input_file, params.key_file);
    } else if(params.genkey_mode) {
        printf("Start genkey\n");
        genKeyMode();
    }

    cleanUp();

    return 0;
}

// Функция генерации ключей

static void genKeyMode() {
    if(CryptGetUserKey(hProv, AT_SIGNATURE, &hPubKey)) {
        printf("A signature key is available.\n");
    } else {
        printf("No signature key is available.\n");

        if(!(GetLastError() == (DWORD)NTE_NO_KEY)) 
            handleError("An error other than NTE_NO_KEY getting signature key.\n");
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n"); 

        // Генерация новой пары ключей

        if(!CryptGenKey(hProv, AT_SIGNATURE, 0, &hPubKey))
            handleError("Error occurred creating a signature key.\n"); 
        printf("Created a signature key pair.\n");
    }
}

// Функция проверки подписи

static void verifySignature(const char * sig, const char * fn, const char * pb) {

    FILE * pubKey;
    FILE * signature;

    DWORD dwSigLen;
    DWORD dwInfoLen;
    DWORD cbHash = 0;

    BYTE *pbSignature = NULL;

    if(!(pubKey = fopen(pb, "rb"))) {
        fclose(pubKey);
        char s[256];
        snprintf(s, 256, "Problem opening the file %s", pb);
        handleError(s);
    }
    
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

    free(pbSignature);
}

// Функция подписи данных

static void signData(const char * fn, const char * sig) {

    FILE * signature;
    FILE * pubKey;

    DWORD dwInfoLen;
    DWORD dwSigLen;
    DWORD cbHash = 0;

    // Экспортирование сведений об открытом ключе в pPubKeyInfo

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen))
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo)
        handleError("Out of memory.\n");

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen))
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
    printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");


    DWORD size = 0;

    // Кодирование структуры pPubKeyInfo

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, NULL, &size)) {
        fclose(pubKey);
        handleError("Error during CryptEncodeObjectEx.");
    }

    BYTE * data = (BYTE*) malloc(size);
    if(!data) {
        handleError("Out of memory.");
    }

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, data, &size)) {
        free(data);
        handleError("Error during CryptEncodeObjectEx.");
    }

    // Запись закодированных данных в файл pubkey.key

    if(!(pubKey = fopen("pubkey.key", "w+b")))
        handleError("Problem opening the file pubkey.key\n");

    fwrite(data, 1, size, pubKey);

    fclose(pubKey);
    free(data);

    // Вычисление хеш-значения от файла

    hashData(fn);

    // Создание подписи

    dwSigLen = 0;
    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen))
        handleError("error during CryptSignHash");
    printf("Signature lenght %d found.\n", dwSigLen);

    pbSignature = (BYTE*) malloc(dwSigLen);
    if(!pbSignature)
        handleError("out of memory.");

    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen))
        handleError("error during CryptSignHash.");
    printf("pbSignature is the hash signature.\n");

    // Создание файла с подписью

    if((signature = fopen(sig, "w+b"))) {
        fwrite(pbSignature, 1, dwSigLen, signature);
        fclose(signature);
    } else {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "could not open file %s", sig);
        handleError(s);
    }
}

// Функция хэширования данных

static void hashData(const char * fn) {

    FILE * data;

    // Создание объекта хэширования
    // CryptCreateHash инициирует хэширование потока данных

    if(!CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash))
        handleError("error during CryptCreatedHash.");
    printf("Hash object created.\n");

    if(!(data = fopen(fn, "r+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "could not open file %s", fn);
        handleError(s);
    }
    printf("The file %s was opened.\n", fn);

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    // Вычисление хэша от данных

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, data);
        if(cbRead)
            if(!CryptHashData(hHash, chFile, cbRead, 0)) {
                fclose(data);
                handleError("cryptHashData failed!");
            }
    } while(!feof(data));

    fclose(data);
}

static void cleanUp(void) {

    free(pPubKeyInfo);
    free(pbHash);
    free(pbSignature);

    if(hPubKey)
        CryptDestroyKey(hPubKey);
    if(hHash)
        CryptDestroyHash(hHash);
    if(hProv)
        CryptReleaseContext(hProv, 0);
}

BOOL parse_args(int argc, char * argv[], progParams * params) {

    memset(params, 0, sizeof(progParams));

    if(argc < 2) {
        printHelp();
        exit(0);
    }

    // Определение введенных команд

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
        printf("crypto-sign-tool: неверная команда \"%s\"\n", argv[1]);
        return FALSE;
    }

    // Определение ключей, которые были заданы
    
    for(int i = 2; i < argc; ++i) {
        if(strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if(i + 1 >= argc) {
                printf("Error parse_args\n");
                return FALSE;
            }
            params->key_file = argv[++i];
        } else if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--in") == 0) {
            if(i + 1 >= argc) {
                printf("Error parse_args\n");
                return FALSE;
            }
            params->input_file = argv[++i];
        } else if(strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--signature") == 0) {
            if(i + 1 >= argc) {
                printf("Error parse_args\n");
                return FALSE;
            }
            params->signature_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--out") == 0){
            if(i + 1 >= argc) {
                printf("Error parse_args\n");
                return FALSE;
            }
            params->output_file = argv[++i];
        } else {
            printf("crypto-sign-tool: неверный ключ \"%s\"\n", argv[i]);
            return FALSE;
        }
    }

}

static void handleError(const char *s) {
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    cleanUp();
    if(!err) err = 1;
    exit(1);
}

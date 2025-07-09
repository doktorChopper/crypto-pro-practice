#include "../include/app.h"
#include <stdio.h>
#include <stdlib.h>

extern HCRYPTPROV hProv;
extern HCRYPTKEY hPubKey;
extern HCRYPTHASH hHash;

extern BYTE *pbHash;

extern PCERT_PUBLIC_KEY_INFO pPubKeyInfo;

// Функция проверки подписи

BOOL verifySignature(const char * sig, const char * fn, const char * pubK) {

    printf("%s %s %s\n", sig, fn, pubK);

    FILE * pubkey = NULL;
    FILE * signature = NULL;
    BYTE * pbKeyDer = NULL;
    DWORD dwKeyDerLen;
    DWORD dwPubKeyInfoSize;

    DWORD dwSigLen;
    DWORD szfile;

    BYTE *pbSignature = NULL;

    if(!(pubkey = fopen(pubK, "r+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "Problem opening the file %s", pubK);
        handleError(s);
        return FALSE;
    }
    
    fseek(pubkey, 0, SEEK_END);
    szfile = ftell(pubkey);
    fseek(pubkey, 0, SEEK_SET);

    pbKeyDer = (BYTE*) malloc(szfile);

    if(!pbKeyDer) {
        fclose(pubkey);
        handleError("Out of memory.");
        return FALSE;
    }

    dwKeyDerLen = fread(pbKeyDer, 1, szfile, pubkey);

    fclose(pubkey);

    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pbKeyDer, dwKeyDerLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &dwPubKeyInfoSize)) {
        free(pbKeyDer);
        handleError("Error during CryptDecodeObject.");
        return FALSE;
    } 

    if(!CryptImportPublicKeyInfo(hProv, X509_PUBLIC_KEY_INFO, pPubKeyInfo, &hPubKey)) {
        free(pbKeyDer);
        handleError("Public key import failed!");
        return FALSE;
    }

    free(pbKeyDer);
    hashData(fn);

    if(!(signature = fopen(sig, "r+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "Problem opening the file %s", sig);
        handleError(s);
        return FALSE;
    }

    fseek(signature, 0, SEEK_END);
    dwSigLen = ftell(signature);
    fseek(signature, 0, SEEK_SET);

    pbSignature = (BYTE*) malloc(dwSigLen);

    DWORD dwTmpLen;

    dwTmpLen = fread(pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    // Проверка подписи

    if(!CryptVerifySignature(hHash, pbSignature, dwTmpLen, hPubKey, NULL, 0)) {
        free(pbSignature);
        handleError("Signature not validated!\n");
        return FALSE;
    }
    printf("The signature has been verified!\n");
    free(pbSignature);

    // if(hPubKey)
    //     CryptDestroyKey(hPubKey);

    return TRUE;
}

// Функция генерации ключей
// Так как задан провайдер PROV_EC_CURVE25519,
// то будет использоваться алгоритм ed25519

BOOL genKeyMode() {
    if(CryptGetUserKey(hProv, AT_SIGNATURE, &hPubKey)) {
        printf("A signature key is available.\n");
        return TRUE;
    }
    printf("No signature key is available.\n");

    if(!(GetLastError() == (DWORD)NTE_NO_KEY)) {
        handleError("An error other than NTE_NO_KEY getting signature key.\n");
        return FALSE;
    }
    printf("Creating a signature key pair...\n"); 

    // Генерация новой пары ключей

    if(!CryptGenKey(hProv, AT_SIGNATURE, 0, &hPubKey)) {
        handleError("Error occurred creating a signature key.\n"); 
        return FALSE;
    }
    printf("Created a signature key pair.\n");
    return FALSE;
}


// Функция подписи данных

BOOL signData(const char * fn, const char * sig) {

    FILE * signature;
    FILE * pubkey;

    BYTE * pbSignature = NULL;

    DWORD dwInfoLen;
    DWORD dwSigLen;

    // Экспортирование сведений об открытом ключе в pPubKeyInfo
    
    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen)) {
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
        return FALSE;
    }
    printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo) {
        handleError("Out of memory.\n");
        return FALSE;
    }

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen)) {
        handleError("Error during CryptExportPublicKeyInfo for signkey.");
        return FALSE;
    }
    printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");

    DWORD size = 0;

    // Кодирование структуры pPubKeyInfo

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, NULL, &size)) {
        handleError("Error during CryptEncodeObjectEx.");
        return FALSE;
    }

    BYTE * pbEncodeObj = (BYTE*) malloc(size);
    if(!pbEncodeObj) {
        handleError("Out of memory.");
        return FALSE;
    }

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, pbEncodeObj, &size)) {
        free(pbEncodeObj);
        handleError("Error during CryptEncodeObjectEx.");
        return FALSE;
    }

    // Запись закодированных данных в файл pubkey.key

    if(!(pubkey = fopen("pubkey.key", "w+b"))) {
        free(pbEncodeObj);
        handleError("Problem opening the file pubkey.key\n");
        return FALSE;
    }
    printf("The file %s was opened.\n", fn);

    fwrite(pbEncodeObj, 1, size, pubkey);

    fclose(pubkey);
    free(pbEncodeObj);

    // Вычисление хеш-значения от файла

    hashData(fn);

    // Создание подписи

    dwSigLen = 0;
    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen)) {
        handleError("error during CryptSignHash");
        return FALSE;
    }
    printf("Signature lenght %d found.\n", dwSigLen);

    pbSignature = (BYTE*) malloc(dwSigLen);
    if(!pbSignature) {
        handleError("out of memory.");
        return FALSE;
    }

    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) {
        free(pbSignature);
        handleError("error during CryptSignHash.");
        return FALSE;
    }
    printf("pbSignature is the hash signature.\n");

    // Запись подписи в файл

    if(!(signature = fopen(sig, "w+b"))) {
        free(pbSignature);
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "could not open file %s", sig);
        handleError(s);
        return FALSE;
    }

    fwrite(pbSignature, 1, dwSigLen, signature);
    fclose(signature);
        free(pbSignature);

    return TRUE;
}

// Функция хэширования данных

void hashData(const char * fn) {

    FILE * data;

    // Создание объекта хэширования
    // CryptCreateHash инициирует хэширование потока данных

    if(!CryptCreateHash(hProv, CALG_NO_HASH, 0, 0, &hHash))
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




void cleanUp(void) {

    free(pPubKeyInfo);
    free(pbHash);

    if(hPubKey)
        CryptDestroyKey(hPubKey);
    if(hHash)
        CryptDestroyHash(hHash);
    if(hProv)
        CryptReleaseContext(hProv, 0);
}

void handleError(const char *s) {
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    cleanUp();
    if(!err) err = 1;
}

#include "../include/app.h"
#include <stdio.h>
#include <stdlib.h>


// Функция проверки подписи

BOOL verifySignature(HCRYPTPROV hProv, const char * sig, const char * fn, const char * pubK) {

    FILE * pubkey = NULL;
    FILE * signature = NULL;

    BYTE * pbKeyDer = NULL;
    BYTE * pbSignature = NULL;

    DWORD szfile;
    DWORD dwSigLen;
    DWORD dwKeyDerLen;
    DWORD dwPubKeyInfoSize;
    DWORD dwTmpLen;

    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;

    HCRYPTKEY hPubKey = 0;
    HCRYPTHASH hHash = 0;

    BOOL result = FALSE;

    printf("%s %s %s\n", sig, fn, pubK);

    if(!(pubkey = fopen(pubK, "r+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "Problem opening the file %s", pubK);
        handleError(hProv, s);
        goto done;
    }
    
    fseek(pubkey, 0, SEEK_END);
    szfile = ftell(pubkey);
    fseek(pubkey, 0, SEEK_SET);

    pbKeyDer = (BYTE*) malloc(szfile);

    if(!pbKeyDer) {
        handleError(hProv, "Out of memory.");
        goto done;
    }

    dwKeyDerLen = fread(pbKeyDer, 1, szfile, pubkey);

    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pbKeyDer, dwKeyDerLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &dwPubKeyInfoSize)) {
        handleError(hProv, "Error during CryptDecodeObject.");
        goto done;
    } 

    if(!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pPubKeyInfo, &hPubKey)) {
        handleError(hProv, "Public key import failed!");
        goto done;
    }

    hashData(hProv, &hHash, fn);

    if(!(signature = fopen(sig, "r+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "Problem opening the file %s", sig);
        handleError(hProv, s);
        goto done;
    }

    fseek(signature, 0, SEEK_END);
    dwSigLen = ftell(signature);
    fseek(signature, 0, SEEK_SET);

    pbSignature = (BYTE*) malloc(dwSigLen);

    dwTmpLen = fread(pbSignature, 1, dwSigLen, signature);

    // Проверка подписи

    if(!CryptVerifySignature(hHash, pbSignature, dwTmpLen, hPubKey, NULL, 0)) {
        handleError(hProv, "Signature not validated!\n");
        goto done;
    }
    printf("The signature has been verified!\n");

    result = TRUE;

    done:
    if(pbKeyDer)
        free(pbKeyDer);
    if(pbSignature)
        free(pbSignature);
    if(pPubKeyInfo)
        LocalFree(pPubKeyInfo);

    if(hPubKey)
        CryptDestroyKey(hPubKey);
    if(hHash)
        CryptDestroyHash(hHash);
    if(pubkey)
        fclose(pubkey);
    if(signature)
        fclose(signature);

    return result;
}


// Функция подписи данных

BOOL signData(HCRYPTPROV hProv, const char * fn, const char * sig) {

    FILE * signature = NULL;

    BYTE * pbSignature = NULL;
    // LPBYTE * ppbKeyBlob = NULL;

    DWORD dwSigLen;
    DWORD dwBlobLen;

    HCRYPTHASH hHash = 0;
    // HCRYPTKEY hPubKey = 0;

    BOOL result = FALSE;


    // Вычисление хеш-значения от файла

    hashData(hProv, &hHash, fn);

    // Создание подписи

    dwSigLen = 0;
    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen)) {
        handleError(hProv, "error during CryptSignHash");
        goto done;
    }
    printf("Signature lenght %d found.\n", dwSigLen);

    pbSignature = (BYTE*) malloc(dwSigLen);
    if(!pbSignature) {
        handleError(hProv, "out of memory.");
        goto done;
    }

    if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) {
        handleError(hProv, "error during CryptSignHash.");
        goto done;
    }
    printf("pbSignature is the hash signature.\n");

    // Запись подписи в файл

    if(!(signature = fopen(sig, "w+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "could not open file %s", sig);
        handleError(hProv, s);
        goto done;
    }
    fwrite(pbSignature, 1, dwSigLen, signature);

    result = TRUE;
    done:
    if(pbSignature)
        free(pbSignature);
    if(hHash)
        CryptDestroyHash(hHash);

    if(signature)
        fclose(signature);
    return result;
}

// Функция удаления контейнера

BOOL deleteContainer(HCRYPTPROV hProv, const char * cont_name) {

    if(!CryptAcquireContext(&hProv, cont_name,  NULL, PROV_EC_CURVE25519, CRYPT_DELETEKEYSET)) {
        if(GetLastError() == (DWORD) NTE_BAD_KEYSET)
            printf("container %s does not exist\n", cont_name);
        else
            handleError(hProv, "Error occured deleating a container.\n");
        return FALSE;
    }
    printf("delete %s container.\n", cont_name);
    return TRUE;
}

// Функция генерации ключей
// Так как задан провайдер PROV_EC_CURVE25519,
// то будет использоваться алгоритм ed25519

BOOL keyGenMode(HCRYPTPROV hProv) {

    HCRYPTKEY hKey = 0;

    BOOL result = FALSE;

    if(CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
        printf("A signature key is available.\n");
        result = TRUE;
        goto done;
    }
    printf("No signature key is available.\n");

    if(!(GetLastError() == (DWORD)NTE_NO_KEY)) {
        handleError(hProv, "An error other than NTE_NO_KEY getting signature key.\n");
        goto done;
    }
    printf("Creating a signature key pair...\n"); 

    // Генерация новой пары ключей

    if(!CryptGenKey(hProv, AT_SIGNATURE, 0, &hKey)) {
        handleError(hProv, "Error occurred creating a signature key.\n"); 
        goto done;
    }
    printf("Created a signature key pair.\n");

    result = TRUE;
    done:
    if(hKey)
        CryptDestroyKey(hKey);

    return result;
}

BOOL getPubKey(HCRYPTPROV hProv, const char * key_fname) {

    DWORD dwInfoLen;
    DWORD size = 0;

    FILE * pubkey = NULL;

    BYTE * pbEncodeObj = NULL;

    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;

    BOOL result = FALSE;

    // Экспортирование сведений об открытом ключе в pPubKeyInfo
    
    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen)) {
        handleError(hProv, "Error during CryptExportPublicKeyInfo for signkey.");
        goto done;
    }
    printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo) {
        handleError(hProv, "Out of memory.\n");
        goto done;
    }

    if(!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen)) {
        handleError(hProv, "Error during CryptExportPublicKeyInfo for signkey.");
        goto done;
    }
    printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");


    // Кодирование структуры pPubKeyInfo

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, NULL, &size)) {
        handleError(hProv, "Error during CryptEncodeObjectEx.");
        goto done;
    }

    pbEncodeObj = (BYTE*) malloc(size);
    if(!pbEncodeObj) {
        handleError(hProv, "Out of memory.");
        goto done;
    }

    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKeyInfo, 0, NULL, pbEncodeObj, &size)) {
        handleError(hProv, "Error during CryptEncodeObjectEx.");
        goto done;
    }

    // Запись закодированных данных в файл pubkey.key

    if(!(pubkey = fopen(key_fname, "w+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "Problem opening the file %s\n", key_fname);
        handleError(hProv, s);
        goto done;
    }
    fwrite(pbEncodeObj, 1, size, pubkey);

    result = TRUE;
    done:
    if(pbEncodeObj)
        free(pbEncodeObj);
    if(pPubKeyInfo)
        free(pPubKeyInfo);

    if(pubkey)
        fclose(pubkey);
    return result;
}



// Функция хэширования данных

void hashData(HCRYPTPROV hProv, HCRYPTHASH * hHash, const char * fn) {

    FILE * data;

    // Создание объекта хэширования
    // CryptCreateHash инициирует хэширование потока данных

    if(!CryptCreateHash(hProv, CALG_NO_HASH, 0, 0, hHash))
        handleError(hProv, "error during CryptCreatedHash.");
    printf("Hash object created.\n");

    if(!(data = fopen(fn, "r+b"))) {
        char s[BUFSIZE];
        snprintf(s, BUFSIZE, "could not open file %s", fn);
        handleError(hProv, s);
    }
    printf("The file %s was opened.\n", fn);

    DWORD cbRead;
    BYTE chFile[BUFSIZE];

    // Вычисление хэша от данных

    do {
        cbRead = (DWORD) fread(chFile, 1, BUFSIZE, data);
        if(cbRead)
            if(!CryptHashData(*hHash, chFile, cbRead, 0)) {
                fclose(data);
                handleError(hProv, "cryptHashData failed!");
            }
    } while(!feof(data));

    fclose(data);
}




void cleanUp(HCRYPTPROV hProv) {
    if(hProv)
        CryptReleaseContext(hProv, 0);
}

void handleError(HCRYPTPROV hProv, const char *s) {
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    // cleanUp(hProv);
    if(!err) err = 1;
}

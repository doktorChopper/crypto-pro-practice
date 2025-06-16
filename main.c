#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*#include "WinCryptEx.h"*/
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"

#include "/opt/cprocsp/include/reader/tchar.h"
#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"


#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\TestKeyCon")

static HCRYPTPROV hProv = 0;
static HCRYPTKEY hKey = 0;
static PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
static BYTE *pbSignature = NULL;
static BYTE *pbHash = NULL;
static HCRYPTHASH hHash = 0;

/*#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\test")*/

#define BUFSIZE 256
#define SHA512LEN 64

static void CleanUp(void);
static void HandleError(const char *);

static void signHash(DWORD *);
static void checkSign(BYTE *, DWORD, DWORD);
/*void CheckSigning();*/


int main(int argc, char *argv[]) {

    BYTE fHash[SHA512LEN];
    CHAR fDigits[] = "0123456789abcdef";
    FILE *hFile;
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    DWORD cbHash = 0;
    DWORD dwSigLen;
    DWORD dwInfoLen;
    FILE *signature;

    BYTE *pbBuffer = (BYTE *)"The data that is to be hashed and signed.";
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer + 1));

    /*if(argc != 2 || argv[1] == NULL)*/
    /*    HandleError("input filename");*/
    /**/
    /*if(!(hFile = fopen(argv[1], "r+b"))) {*/
    /*    char s[BUFSIZE];*/
    /*    if(snprintf(s, BUFSIZE, "could not open file %s", argv[1]) < 0)*/
    /*        printf("error snprintf");*/
    /*    HandleError(s);*/
    /*}*/
    /*printf("The file %s was opened.\n", argv[1]);*/

    if(CryptAcquireContextA(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, 0))
        printf("CSP is acquired!\n");
    else
        HandleError("Error during CryptAcquireContext");

    if(CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &dwInfoLen)) 
        printf("Size of the CERT_PUBLIC_KEY_INFO determined.\n");
    else
        HandleError("Error during CryptExportPublicKeyInfo for signkey.");

    pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(dwInfoLen);
    if(!pPubKeyInfo)
        HandleError("Out of memory.\n");

    if(CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pPubKeyInfo, &dwInfoLen))
        printf("Contents have been written to the CERT_PUBLIC_KEY_INFO.\n");
    else
        HandleError("Error during CryptExportPublicKeyInfo for signkey.");

    if(CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
        printf("Hash object created.\n");
    else
        HandleError("Error during created hash.");

    if(CryptGetHashParam(hHash, HP_OID, NULL, &cbHash, 0))
        printf("Size of the BLOB determined.\n");
    else
        HandleError("Error during CryptGetHashParam.");

    pbHash = (BYTE *)malloc(cbHash);
    if(!pbHash)
        HandleError("Out of memory.\n");

    if(CryptGetHashParam(hHash, HP_OID, pbHash, &cbHash, 0))
        printf("Parameters have been written to the pbHash.\n");
    else
        HandleError("Error during CryptGetHashParam.");

    if(CryptHashData(hHash, pbBuffer, dwBufferLen, 0))
        printf("The data buffer has been hashed.\n");
    else
        HandleError("Error during CryptHashData");

    signHash(&dwSigLen);

    if(!(signature = fopen("signature.txt", "w+b")))
        HandleError("Problem opening the file signature.txt\n");

    fwrite(pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    if(hHash)
        CryptDestroyHash(hHash);

    printf("The hash object has been destroyed.\n");
    printf("The signing phase of this program is completed.\n\n");

    /*fclose(hFile);*/



    /*signHash(&dwSigLen);*/
    checkSign(pbBuffer, dwBufferLen, dwSigLen);
    CleanUp();

    return 0;
}

void CleanUp(void) {

    free(pbSignature);
    free(pbHash);
    free(pPubKeyInfo);

    if(hHash)
        CryptDestroyHash(hHash);

    if(hKey)
        CryptDestroyKey(hKey);

    if(hProv)
        CryptReleaseContext(hProv, 0);
}

void HandleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    CleanUp();
    if(!err) err = 1;
    exit(err);
}

static void checkSign(BYTE *pbBuffer, DWORD dwBufferLen, DWORD dwSigLen) {
    
    if(CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pPubKeyInfo, &hKey))
        printf("The key has been imported.\n");
    else
        HandleError("Public key import failed");

    if(CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
        printf("The hash object has been recreated.\n");
    else
        HandleError("Error during CryptCreateHash.");

    if(CryptHashData(hHash, pbBuffer, dwBufferLen, 0))
        printf("The new hash has been created.\n");
    else
        HandleError("Error during CryptHashData");

    if(CryptVerifySignature(hHash, pbSignature, dwSigLen, hKey, NULL, 0))
        printf("The signature has been verified.\n");
    else
        HandleError("Signature not validate!\n");

    if(hHash)
        CryptDestroyHash(hHash);
}


static void signHash(DWORD *dwSigLen) {

    *dwSigLen = 0;
    if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, dwSigLen))
        printf("Signature lenght %d found.\n", *dwSigLen);
    else
        HandleError("Error during CryptSignHash");

    pbSignature = (BYTE *) malloc(*dwSigLen);
    if(!pbSignature)
        HandleError("Out of memory.");

    if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, dwSigLen))
        printf("pbSignature is the hash signature.\n");
    else
        HandleError("Error during CryptSignHash.");
}

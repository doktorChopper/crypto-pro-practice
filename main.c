#include <stdio.h>
#include <stdlib.h>
/*#include "WinCryptEx.h"*/
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"

#include "/opt/cprocsp/include/reader/tchar.h"
#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"


#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\TestKeyCon")

static HCRYPTPROV hProv = 0;
static HCRYPTKEY hKey = 0;
static PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
static BYTE *pbSignature = NULL;

/*#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\test")*/

static void CleanUp(void);
static void HandleError(const char *);

void Signing();
void CheckSigning();

#define BUFSIZE 256
#define SHA512LEN 64

int main(int argc, char *argv[]) {

    BYTE fHash[SHA512LEN];
    CHAR fDigits[] = "0123456789abcdef";
    FILE *hFile;
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;
    DWORD dwSigLen;
    DWORD dwInfoLen;
    FILE *signature;

    if(argc != 2 || argv[1] == NULL)
        HandleError("input filename");

    if(!(hFile = fopen(argv[1], "r+b"))) {
        char s[BUFSIZE];
        if(snprintf(s, BUFSIZE, "could not open file %s", argv[1]) < 0)
            printf("error snprintf");
        HandleError(s);
    }
    printf("The file %s was opened.\n", argv[1]);

    /*if(CryptAcquireContextA(&hProv, "TEST", NULL, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)) {*/
    /*    printf("CSP is acquired!\n");*/
    /*}*/

    if(CryptAcquireContextA(&hProv, CONTAINER, NULL, PROV_GOST_2012_256, 0))
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

    // CalcHash

    DWORD cbRead = 0;
    BYTE file[BUFSIZE];

    if(!CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash))
        HandleError("CryptCreateHash failed!");
    do {
        cbRead = (DWORD) fread(file, 1, BUFSIZE, hFile);
        
        if(cbRead) {
            if(!CryptHashData(hHash, file, BUFSIZE, 0)) {
                CryptDestroyHash(hHash);
                HandleError("CryptHashData failed");
            }
        }
    } while (!feof(hFile));

    cbHash = SHA512LEN;
    if(!CryptGetHashParam(hHash, HP_HASHVAL, fHash, &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        HandleError("CryptGetHashParam failed"); 
    }

    printf("SHA512 hash of file %s is: ", argv[1]);
    for(int i = 0; i < cbHash; i++) {
        printf("%c%c", fDigits[fHash[i] >> 4],
            fDigits[fHash[i] & 0xf]);
    }
    printf("\n");

    dwSigLen = 0;
    if(CryptSignHashA(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen))
        printf("Signature lenght %d found.\n", dwSigLen);
    else
        HandleError("Error during CryptSignHash.");

    pbSignature = (BYTE *) malloc(dwSigLen);
    if(!pbSignature)
        HandleError("Out of memory.");

    if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen))
        printf("pbSignature is the hash signature.\n");
    else
        HandleError("Error during CryptSignHash.");

    if(!(signature = fopen("signature.txt", "w+b")))
        HandleError("Problem opening the file signature.txt\n");

    fwrite(pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    if(hHash)
        CryptDestroyHash(hHash);

    printf("The hash object has been destroyed.\n");
    printf("The signing phase of this program is completed.\n\n");

    fclose(hFile);
    CleanUp();

    return 0;
}

void CleanUp(void) {

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

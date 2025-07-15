#ifndef _APP_H_
#define _APP_H_

// #include "WinCryptEx.h"
#include "/opt/cprocsp/include/cpcsp/WinCryptEx.h"
/*#include "CSP_WinCrypt.h"*/
#include "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"


/*#include "reader/tchar.h"*/
#include "/opt/cprocsp/include/reader/tchar.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wchar.h>

#define BUFSIZE 256

void handleError(HCRYPTPROV, const char *); // функция обработки ошибок
void cleanUp(HCRYPTPROV); // функция освобождения памяти, закрытия дескрипторов и контекста

BOOL signData(HCRYPTPROV, const char *, const char *); // функция подписи данных
BOOL verifySignature(HCRYPTPROV, const char *, const char *, const char *); // функция проверки подписи
void hashData(HCRYPTPROV, HCRYPTHASH *, const char *); // хэширование данных (CALG_NO_HASH)
BOOL keyGenMode(HCRYPTPROV); // функция генерации ключей ed25519
BOOL getPubKey(HCRYPTPROV, const char *);
BOOL deleteContainer(HCRYPTPROV, const char *);

#endif // _APP_H_

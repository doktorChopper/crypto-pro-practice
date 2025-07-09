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

void handleError(const char *); // функция обработки ошибок
void cleanUp(void); // функция освобождения памяти, закрытия дескрипторов и контекста

BOOL signData(const char *, const char *); // функция подписи данных
BOOL verifySignature(const char *, const char *, const char *); // функция проверки подписи
void hashData(const char *); // хэширование данных (CALG_NO_HASH)
BOOL genKeyMode(); // функция генерации ключей ed25519

#endif // _APP_H_

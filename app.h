#ifndef _APP_H_
#define _APP_H_

void handleError(const char *); // функция обработки ошибок
void cleanUp(void); // функция освобождения памяти, закрытия дескрипторов и контекста

void signData(const char *, const char *); // функция подписи данных
void verifySignature(const char *, const char *, const char *); // функция проверки подписи
void hashData(const char *); // хэширование данных (CALG_NO_HASH)
void genKeyMode(); // функция генерации ключей ed25519

#endif // _APP_H_

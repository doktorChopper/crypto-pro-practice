#include "../include/app.h"
#include <stdio.h>
#include <stdlib.h>

#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\Curve")

// структура для парсинга параметров командной строки

typedef struct {
    char * key_file;
    char * signature_file;
    char * input_file;
    char * output_file;
    BOOL verify_mode;
    BOOL sign_mode;
    BOOL genkey_mode;
    BOOL getkey_mode;
    BOOL delcont_mode;
} progParams;

void printHelp(void);
BOOL parse_args(int, char *[], progParams *);

void printHelp(void) {
    printf("\nCryptoSignTool - утилита для работы с электронной подписью\n\n"
            "Использование: \n"
            "   crypto-sign-tool [команда] [параметры]\n\n"
            "Команды: \n"
            "   keygen      Генерирование ключей\n"
            "   getkey      Экспортировать открытый ключ\n"
            "   del-cont    удалить контейнер с ключами\n"
            "   sign        Создание подписи для файла\n"
            "   verify      Проверка подписи\n\n"
            "Параметры: \n"
            "   -k, --key <файл>        Файл открытого ключа (.key)\n"
            "   -i, --in <файл>         Входной файл для подписи/проверки\n"
            "   -s, --signature <файл>  Файл с электронной подписью (только для verify)\n"
            "   -o, --out <файл>        Выходной файл\n\n"
            "Примеры использования:\n"
            "   crypto-sign-tool sign --in <file.txt> --out <signature.sig>\n"
            "   crypto-sign-tool verify -s <signature.sig> -i <file.txt> -k <pubkey.key>\n"
            "   crypto-sign-tool getkey -k <pubkey.key>\n"
            "   crypto-sign-tool del-con\n"
            "   crypto-sign-tool keygen \n\n");
}


int main(int argc, char * argv[]) {

    HCRYPTPROV hProv = 0;
    progParams params; 

    // Парсинг команд и параметров

    if(!parse_args(argc, argv, &params)) {
        printf("Используйте --help для справки\n");
        exit(1);
    }

    // Получение дескриптора криптопровайдера
    // Если не существует контейнера по заданному имени, то создается новый контейнер

    if(CryptAcquireContext(&hProv, CONTAINER,  NULL, PROV_EC_CURVE25519, 0)) {
        printf("A cryptcontext with the %s key container has been acquired.\n", CONTAINER);
    } else {
    	if(!CryptAcquireContext(&hProv, CONTAINER, NULL, PROV_EC_CURVE25519, CRYPT_NEWKEYSET)) 
            handleError(hProv, "Could not create a new key container.");
        printf("A new key container has been created.\n");
    }

    LPSTR pszContainerName;
    DWORD dwContainerNameLen;

    // получение имени контейнера

    if(!CryptGetProvParam(hProv, PP_CONTAINER, NULL, &dwContainerNameLen, 0))
        handleError(hProv, "Error occurred getting the key container name.");

    pszContainerName = (char *)malloc((dwContainerNameLen + 1));

    if(!CryptGetProvParam(hProv, PP_CONTAINER, (LPBYTE)pszContainerName, &dwContainerNameLen, 0)) {
        free(pszContainerName);
        handleError(hProv, "Error occurred getting the key container name.");
    }
    printf("A crypto context has been acquired and the name on the key container is %s\n\n", pszContainerName);
    free(pszContainerName);

    // выбор функции по введенной команде

    if(params.sign_mode) {
        printf("Start signing data: %s\n", params.input_file);
        if(!signData(hProv, params.input_file, params.output_file))
            exit(1);
    } else if(params.verify_mode) {
        printf("Start verify signature\n");
        if(!verifySignature(hProv, params.signature_file, params.input_file, params.key_file))
            exit(1);
    } else if(params.genkey_mode) {
        printf("Start genkey\n");
        if(!keyGenMode(hProv))
            exit(1);
    } else if(params.getkey_mode) {
        printf("Start export publickey\n");
        if(!getPubKey(hProv, params.key_file))
            exit(1);
    } else if(params.delcont_mode) {
        printf("Start delete container\n");
        if(!deleteContainer(hProv, CONTAINER))
            exit(1);
    }

    cleanUp(hProv);

    return 0;
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
    else if(strcmp(argv[1], "keygen") == 0)
        params->genkey_mode = TRUE;
    else if(strcmp(argv[1], "getkey") == 0)
        params->getkey_mode = TRUE;
    else if(strcmp(argv[1], "del-cont") == 0)
        params->delcont_mode = TRUE;
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



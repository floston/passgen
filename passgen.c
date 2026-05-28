/*
 * passgen.c - консольное приложение для генерации паролей
 * 
 * Компиляция (MinGW): gcc -o passgen.exe passgen.c -lbcrypt
 * Компиляция (Linux):  gcc -o passgen passgen.c
 * Использование: passgen [ключи]
 *
 * Ключи:
 *   -l, --length N    Длина пароля (по умолчанию 12)
 *   -t, --type TYPE   Тип сложности: simple, medium, complex (по умолчанию medium)
 *   -n, --count N     Количество паролей (по умолчанию 1)
 *   -o, --output FILE Вывод в файл (по умолчанию stdout)
 *   -h, --help        Показать справку
 *
 * Примеры:
 *   passgen.exe                     # пароль средней сложности длиной 12
 *   passgen.exe -l 16               # пароль средней сложности длиной 16
 *   passgen.exe -t simple           # простой пароль длиной 12
 *   passgen.exe -l 20 -t complex    # сложный пароль длиной 20
 *   passgen.exe -n 5                # 5 паролей средней сложности
 *   passgen.exe -n 10 -o passwords.txt  # 10 паролей в файл
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Платформо-зависимые включения */
#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

/* Константы */
#define MIN_LENGTH          6
#define MAX_LENGTH          128
#define DEFAULT_LENGTH      12
#define DEFAULT_COUNT       1
#define MAX_CHARSET_SIZE    256
#define MAX_OUTPUT_LINE     (MAX_LENGTH + 1)

/* Наборы символов для разных уровней сложности */
static const char * const CHARSET_LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
static const char * const CHARSET_UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";
static const char * const CHARSET_DIGITS = "23456789";
static const char * const CHARSET_SPECIAL = "@$%&*!#?";

/* Типы сложности */
typedef enum {
    COMPLEXITY_SIMPLE,
    COMPLEXITY_MEDIUM,
    COMPLEXITY_COMPLEX
} Complexity;

/* Структура для параметров генерации */
typedef struct {
    int length;
    int count;
    Complexity complexity;
    const char *output_file;
} GeneratorParams;

/* Прототипы функций */
static int parse_args(int argc, char *argv[], GeneratorParams *params);
static void print_help(const char *program_name);
static int crypto_random(uint8_t *buffer, size_t length);
static uint32_t crypto_random_uniform(uint32_t upper_bound);
static void generate_password(char *password, size_t length, Complexity complexity);
static int contains_required(const char *password, Complexity complexity);
static void secure_zero(void *ptr, size_t len);
#ifdef _WIN32
static void setup_console_encoding(void);
#endif

/*
 * Основная функция
 */
int main(int argc, char *argv[]) {
    GeneratorParams params;
    char password[MAX_OUTPUT_LINE];
    FILE *output = stdout;
    int i;
    int ret = 0;

#ifdef _WIN32
    /* Установка UTF-8 кодировки для консоли Windows */
    setup_console_encoding();
#endif

    /* Разбор аргументов командной строки */
    if (parse_args(argc, argv, &params) != 0) {
        return 1;
    }

    /* Открытие выходного файла, если указан */
    if (params.output_file != NULL) {
        output = fopen(params.output_file, "w");
        if (output == NULL) {
            fprintf(stderr, "Ошибка: не удалось открыть файл '%s'\n", params.output_file);
            return 1;
        }
    }

    /* Генерация паролей */
    for (i = 0; i < params.count; i++) {
        generate_password(password, params.length, params.complexity);
        
        if (params.count > 1) {
            fprintf(output, "%d: %s\n", i + 1, password);
        } else {
            fprintf(output, "%s\n", password);
        }
    }

    /* Очистка и выход */
    secure_zero(password, sizeof(password));
    
    if (output != stdout) {
        fclose(output);
    }
    
    return ret;
}

/*
 * Установка кодировки консоли Windows в UTF-8
 */
#ifdef _WIN32
static void setup_console_encoding(void) {
    /* Устанавливаем кодовую страницу UTF-8 для консоли */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    /* Включаем поддержку виртуального терминала для корректного вывода */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
}
#endif

/*
 * Вывод справки
 */
static void print_help(const char *program_name) {
    printf("Использование: %s [ключи]\n\n", program_name);
    printf("Ключи:\n");
    printf("  -l, --length N    Длина пароля (%d-%d, по умолчанию %d)\n", 
           MIN_LENGTH, MAX_LENGTH, DEFAULT_LENGTH);
    printf("  -t, --type TYPE   Тип сложности: simple, medium, complex (по умолчанию medium)\n");
    printf("  -n, --count N     Количество паролей (по умолчанию %d)\n", DEFAULT_COUNT);
    printf("  -o, --output FILE Вывод в файл (по умолчанию stdout)\n");
    printf("  -h, --help        Показать эту справку\n");
    printf("\nПримеры:\n");
    printf("  %s                     # пароль средней сложности длиной 12\n", program_name);
    printf("  %s -l 16               # пароль средней сложности длиной 16\n", program_name);
    printf("  %s -t simple           # простой пароль длиной 12\n", program_name);
    printf("  %s -l 20 -t complex    # сложный пароль длиной 20\n", program_name);
    printf("  %s -n 5                # 5 паролей средней сложности\n", program_name);
    printf("  %s -n 10 -o passwords.txt  # 10 паролей в файл\n", program_name);
}

/*
 * Разбор аргументов командной строки
 * Возвращает: 0 - успех, 1 - ошибка или справка
 */
static int parse_args(int argc, char *argv[], GeneratorParams *params) {
    int i;

    /* Установки по умолчанию */
    params->length = DEFAULT_LENGTH;
    params->count = DEFAULT_COUNT;
    params->complexity = COMPLEXITY_MEDIUM;
    params->output_file = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 1;
        }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--length") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Ошибка: ключ '%s' требует аргумента\n", argv[i]);
                return 1;
            }
            params->length = atoi(argv[++i]);
            if (params->length < MIN_LENGTH || params->length > MAX_LENGTH) {
                fprintf(stderr, "Ошибка: длина пароля должна быть от %d до %d\n", 
                        MIN_LENGTH, MAX_LENGTH);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Ошибка: ключ '%s' требует аргумента\n", argv[i]);
                return 1;
            }
            const char *type = argv[++i];
            if (strcmp(type, "simple") == 0) {
                params->complexity = COMPLEXITY_SIMPLE;
            } else if (strcmp(type, "medium") == 0) {
                params->complexity = COMPLEXITY_MEDIUM;
            } else if (strcmp(type, "complex") == 0) {
                params->complexity = COMPLEXITY_COMPLEX;
            } else {
                fprintf(stderr, "Ошибка: неизвестный тип '%s'. Допустимые: simple, medium, complex\n", type);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--count") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Ошибка: ключ '%s' требует аргумента\n", argv[i]);
                return 1;
            }
            params->count = atoi(argv[++i]);
            if (params->count < 1 || params->count > 1000) {
                fprintf(stderr, "Ошибка: количество паролей должно быть от 1 до 1000\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Ошибка: ключ '%s' требует аргумента\n", argv[i]);
                return 1;
            }
            params->output_file = argv[++i];
        }
        else {
            fprintf(stderr, "Ошибка: неизвестный ключ '%s'. Используйте -h для справки.\n", argv[i]);
            return 1;
        }
    }

    return 0;
}

/*
 * Криптографически стойкий ГСЧ
 * Возвращает: 0 - успех, -1 - ошибка
 */
static int crypto_random(uint8_t *buffer, size_t length) {
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        NULL,                   /* Провайдер по умолчанию */
        buffer,                 /* Буфер для результата */
        (ULONG)length,          /* Длина буфера */
        BCRYPT_USE_SYSTEM_PREFERRED_RNG  /* Использовать системный ГСЧ */
    );
    return (status == 0) ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, length);
    close(fd);
    
    return (bytes_read == (ssize_t)length) ? 0 : -1;
#endif
}

/*
 * Генерация равномерно распределённого случайного числа в диапазоне [0, upper_bound)
 * Использует rejection sampling для устранения модулярной предвзятости
 */
static uint32_t crypto_random_uniform(uint32_t upper_bound) {
    if (upper_bound == 0) {
        return 0;
    }
    
    /* Вычисляем максимальное значение, которое делится на upper_bound без остатка */
    uint32_t mask = upper_bound - 1;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    
    uint32_t result;
    uint8_t random_bytes[4];
    
    do {
        if (crypto_random(random_bytes, sizeof(random_bytes)) != 0) {
            /* В случае ошибки возвращаем 0 (не должно произойти) */
            return 0;
        }
        result = ((uint32_t)random_bytes[0] << 24) |
                 ((uint32_t)random_bytes[1] << 16) |
                 ((uint32_t)random_bytes[2] << 8)  |
                 ((uint32_t)random_bytes[3]);
        result &= mask;
    } while (result >= upper_bound);
    
    return result;
}

/*
 * Генерация пароля
 */
static void generate_password(char *password, size_t length, Complexity complexity) {
    const char *charsets[] = {CHARSET_LOWERCASE, CHARSET_UPPERCASE, CHARSET_DIGITS, CHARSET_SPECIAL};
    int charset_count = 0;
    int required_from_each = 0;
    int i, pos;

    /* Определение набора символов в зависимости от сложности */
    switch (complexity) {
        case COMPLEXITY_SIMPLE:
            /* Буквы нижнего регистра только */
            charsets[0] = CHARSET_LOWERCASE;
            charset_count = 1;
            required_from_each = 0;
            break;

        case COMPLEXITY_MEDIUM:
            /* Буквы нижнего и верхнего регистра + цифры */
            charset_count = 3;
            required_from_each = 0;
            break;

        case COMPLEXITY_COMPLEX:
            /* Все наборы */
            charset_count = 4;
            required_from_each = 1; /* Требуется хотя бы по одному из каждого */
            break;
    }

    /* Формируем общий набор доступных символов */
    char all_chars[MAX_CHARSET_SIZE] = {0};
    size_t all_chars_len = 0;
    for (i = 0; i < charset_count; i++) {
        const char *s = charsets[i];
        while (*s && all_chars_len < MAX_CHARSET_SIZE - 1) {
            all_chars[all_chars_len++] = *s++;
        }
    }
    all_chars[all_chars_len] = '\0';

    /* Генерация случайного пароля с равномерным распределением */
    for (pos = 0; pos < (int)length; pos++) {
        uint32_t idx = crypto_random_uniform((uint32_t)all_chars_len);
        password[pos] = all_chars[idx];
    }
    password[length] = '\0';

    /* Если требуется, обеспечиваем наличие символов из каждого набора */
    if (required_from_each > 0) {
        for (i = 0; i < charset_count; i++) {
            /* Выбираем случайную позицию, заменяем символ на из нужного набора */
            pos = (int)crypto_random_uniform((uint32_t)length);
            const char *s = charsets[i];
            int char_len = (int)strlen(s);
            uint32_t idx = crypto_random_uniform((uint32_t)char_len);
            password[pos] = s[idx];
        }
    }

    /* Дополнительная проверка: пароль должен соответствовать требованиям сложности */
    while (!contains_required(password, complexity)) {
        for (i = 0; i < charset_count; i++) {
            if (strlen(charsets[i]) > 0) {
                pos = (int)crypto_random_uniform((uint32_t)length);
                const char *s = charsets[i];
                int char_len = (int)strlen(s);
                uint32_t idx = crypto_random_uniform((uint32_t)char_len);
                password[pos] = s[idx];
            }
        }
    }
}

/*
 * Проверка, содержит ли пароль необходимые символы для заданной сложности
 */
static int contains_required(const char *password, Complexity complexity) {
    switch (complexity) {
        case COMPLEXITY_SIMPLE:
            /* Для простых - достаточно, чтобы все были из нижнего регистра */
            while (*password) {
                if (*password < 'a' || *password > 'z') return 0;
                password++;
            }
            return 1;

        case COMPLEXITY_MEDIUM:
            /* Для средней - должны быть и заглавные буквы, и цифры */
            {
                int has_upper = 0, has_digit = 0;
                while (*password) {
                    if (*password >= 'A' && *password <= 'Z') has_upper = 1;
                    if (*password >= '0' && *password <= '9') has_digit = 1;
                    password++;
                }
                return has_upper && has_digit;
            }

        case COMPLEXITY_COMPLEX:
            /* Для сложной - должны быть заглавные, строчные, цифры и спецсимволы */
            {
                int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
                const char *special = CHARSET_SPECIAL;
                while (*password) {
                    if (*password >= 'a' && *password <= 'z') has_lower = 1;
                    else if (*password >= 'A' && *password <= 'Z') has_upper = 1;
                    else if (*password >= '0' && *password <= '9') has_digit = 1;
                    else {
                        const char *s = special;
                        while (*s) {
                            if (*password == *s++) { has_special = 1; break; }
                        }
                    }
                    if (has_upper && has_lower && has_digit && has_special) return 1;
                    password++;
                }
                return 0;
            }
    }
    return 0;
}

/*
 * Безопасная очистка памяти (не может быть оптимизирована компилятором)
 */
static void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

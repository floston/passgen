# Makefile для passgen
# Поддерживает Windows (MinGW) и Linux

# Определяем платформу
ifeq ($(OS),Windows_NT)
    TARGET = passgen.exe
    CC = gcc
    CFLAGS = -Wall -Wextra -O2
    LDFLAGS = -lbcrypt
    RM = del /Q
else
    TARGET = passgen
    CC = gcc
    CFLAGS = -Wall -Wextra -O2
    LDFLAGS =
    RM = rm -f
endif

# Исходные файлы
SRC = passgen.c
OBJ = $(SRC:.c=.o)

# Цель по умолчанию
all: $(TARGET)

# Сборка
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Очистка
clean:
	$(RM) $(TARGET) $(OBJ)

# Пересборка
rebuild: clean all

# Тесты
test: $(TARGET)
	@echo "=== Тест 1: Пароль по умолчанию ==="
	./$(TARGET)
	@echo ""
	@echo "=== Тест 2: Простой пароль ==="
	./$(TARGET) -t simple
	@echo ""
	@echo "=== Тест 3: Сложный пароль длиной 20 ==="
	./$(TARGET) -l 20 -t complex
	@echo ""
	@echo "=== Тест 4: 5 паролей ==="
	./$(TARGET) -n 5
	@echo ""
	@echo "=== Тест 5: Вывод в файл ==="
	./$(TARGET) -n 3 -o test_output.txt
	@cat test_output.txt
	@$(RM) test_output.txt
	@echo ""
	@echo "=== Все тесты пройдены ==="

.PHONY: all clean rebuild test

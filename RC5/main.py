import tkinter as tk
from tkinter import ttk
import os

# RC5 параметры по умолчанию
word_size = 32  # Размер слова
DEFAULT_ROUNDS = 12  # Количество раундов
KEY_SIZE = 16  # Размер ключа по дефолту

# Константы для расширения ключа
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def shift_left(x, y, size=word_size):
    first = (x << y) & (2 ** size - 1)
    second = x >> (size - y)
    return first | second


def shift_right(x, y, size=word_size):
    first = x >> y
    second = (x << (size - y)) & (2 ** size - 1)
    return first | second


def key_schedule(key, rounds=DEFAULT_ROUNDS):
    L = [int.from_bytes(key[i:i + 4], byteorder='little') for i in range(0, len(key), 4)]
    S = [(P32 + i * Q32) & 0xFFFFFFFF for i in range(2 * (rounds + 1))]
    A = B = i = j = 0
    v = 3 * max(len(L), len(S))
    for _ in range(v):
        A = S[i] = shift_left((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = L[j] = shift_left((L[j] + A + B) & 0xFFFFFFFF, (A + B) & 31)
        i = (i + 1) % len(S)
        j = (j + 1) % len(L)
    return S


# Шифрование RC5
def rc5_encrypt(block, S, rounds=DEFAULT_ROUNDS):
    A = int.from_bytes(block[:4], byteorder='little')
    B = int.from_bytes(block[4:], byteorder='little')
    l = word_size
    # первое (но последнее) преобразование с S[2i]
    A = (A + S[0]) % (2**l)
    B = (B + S[1]) % (2**l)
    # Основные раунды c S2i+1
    for i in range(1, rounds + 1):
        A = (shift_left((A ^ B), B % l, l) + S[2 * i]) % (2**l)
        B = (shift_left((B ^ A), A % l, l) + S[2 * i + 1]) % (2**l)
    block = A.to_bytes(4, byteorder='little') + B.to_bytes(4, byteorder='little')
    return block


# Дешифрование RC5
def rc5_decrypt(block, S, rounds=DEFAULT_ROUNDS):
    A = int.from_bytes(block[:4], byteorder='little')
    B = int.from_bytes(block[4:], byteorder='little')
    l = word_size
    # Основные раунды (в обратном порядке) c S[2i+1]
    for i in range(rounds, 0, -1):
        B = shift_right((B - S[2 * i + 1]) % (2**l), A % l, l) ^ A
        A = shift_right((A - S[2 * i]) % (2**l), B % l, l) ^ B
    #первое (но последнее) преобразование с S2i
    B = (B - S[1]) % (2 ** l)
    A = (A - S[0]) % (2 ** l)
    block = A.to_bytes(4, byteorder='little') + B.to_bytes(4, byteorder='little')
    return block


def generate_key():
    try:
        key_size = int(key_size_input.get())
        if key_size <= 0:
            raise ValueError("Размер ключа должен быть положительным числом.")
        if key_size >= 256:
            raise ValueError("Размер ключа должен быть меньше 256.")
        key = os.urandom(key_size)
        key_label.set(f"Ключ (hex): {key.hex()}")
        global encryption_key
        encryption_key = key
    except Exception as e:
        key_label.set(f"Ошибка: {e}")


def encrypt_message():
    try:
        message = message_input.get("1.0", tk.END).strip()
        if not message:
            raise ValueError("Введите сообщение для шифрования.")

        message_bytes = message.encode("utf-8")
        key = encryption_key[:KEY_SIZE]
        padded_message = message_bytes + b" " * (8 - len(message_bytes) % 8)  # Padding для кратности 8
        cipher_text = b""

        S = key_schedule(key)
        for i in range(0, len(padded_message), 8):
            cipher_text += rc5_encrypt(padded_message[i:i + 8], S)

        encrypted_output.set(cipher_text.hex())
    except Exception as e:
        encrypted_output.set(f"Ошибка: {e}")


def decrypt_message():
    try:
        cipher_hex = encrypted_input.get("1.0", tk.END).strip()
        if not cipher_hex:
            raise ValueError("Введите зашифрованный текст.")

        cipher_bytes = bytes.fromhex(cipher_hex)
        key = encryption_key[:KEY_SIZE]
        decrypted_message = b""

        S = key_schedule(key)
        for i in range(0, len(cipher_bytes), 8):
            decrypted_message += rc5_decrypt(cipher_bytes[i:i + 8], S)

        decrypted_output.set(decrypted_message.decode("utf-8").rstrip())
    except Exception as e:
        decrypted_output.set(f"Ошибка: {e}")


def copy(content):
    root.clipboard_clear()
    root.clipboard_append(content)
    root.update()


def paste(entry):
    entry.delete("1.0", tk.END)
    entry.insert("1.0", root.clipboard_get())


# Инициализация окна
root = tk.Tk()
root.title("RC5 Шифрование (мне охота плакать уже как я завтра на пары проснусь)")
root.geometry("600x800")

# Параметры
params_frame = ttk.Frame(root)
params_frame.pack(pady=5, fill=tk.X)

ttk.Label(params_frame, text="Размер ключа (байт):").pack(anchor=tk.W)
key_size_input = ttk.Entry(params_frame)
key_size_input.pack(fill=tk.X, padx=5, pady=5)
ttk.Button(params_frame, text="Сгенерировать ключ", command=generate_key).pack(pady=5)

key_label = tk.StringVar()
ttk.Label(params_frame, textvariable=key_label, foreground="blue").pack(fill=tk.X)

# Ввод сообщения
message_frame = ttk.Frame(root)
message_frame.pack(pady=5, fill=tk.X)
ttk.Label(message_frame, text="Введите сообщение для шифрования:").pack(anchor=tk.W)
message_input = tk.Text(message_frame, height=4, wrap=tk.WORD)
message_input.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(message_frame, text="Копировать", command=lambda: copy(message_input.get("1.0", tk.END).strip())).pack(side=tk.LEFT, padx=2)
ttk.Button(message_frame, text="Вставить", command=lambda: paste(message_input)).pack(side=tk.LEFT, padx=2)

ttk.Button(root, text="Зашифровать!!!1", command=encrypt_message).pack(pady=5)

# Вывод зашифрованного текста
encrypted_frame = ttk.Frame(root)
encrypted_frame.pack(pady=5, fill=tk.X)
encrypted_output = tk.StringVar()
ttk.Label(encrypted_frame, textvariable=encrypted_output, foreground="blue", wraplength=550, anchor=tk.W, justify=tk.LEFT).pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(encrypted_frame, text="Копировать", command=lambda: copy(encrypted_output.get())).pack(side=tk.LEFT, padx=5)

# Ввод зашифрованного текста
encrypted_frame = ttk.Frame(root)
encrypted_frame.pack(pady=5, fill=tk.X)
ttk.Label(encrypted_frame, text="Введите зашифрованное сообщение:").pack(anchor=tk.W)
encrypted_input = tk.Text(encrypted_frame, height=4, wrap=tk.WORD)
encrypted_input.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(encrypted_frame, text="Копировать", command=lambda: copy(encrypted_input.get("1.0", tk.END).strip())).pack(side=tk.LEFT, padx=2)
ttk.Button(encrypted_frame, text="Вставить", command=lambda: paste(encrypted_input)).pack(side=tk.LEFT, padx=2)

ttk.Button(root, text="Расшифровать!!!1", command=decrypt_message).pack(pady=5)

# Вывод расшифровки
decrypted_output = tk.StringVar()
ttk.Label(root, textvariable=decrypted_output, foreground="green", wraplength=550, anchor=tk.W, justify=tk.LEFT).pack(fill=tk.BOTH, padx=5, pady=3, expand=True)

# Инициализация ключа
encryption_key = os.urandom(KEY_SIZE)

root.mainloop()

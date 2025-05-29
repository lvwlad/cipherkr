#include "exporter.h"
#include <QFile>
#include <QTextStream>

QString getCipherDescription(const QString& cipherName) {
    if (cipherName == "Caesar") {
        return "Шифр Цезаря: каждый символ текста сдвигается на фиксированное количество позиций в алфавите. Ключ определяет величину сдвига.";
    } else if (cipherName == "Atbash") {
        return "Шифр Атбаш: каждый символ заменяется на противоположный в алфавите (например, A на Z, B на Y). Ключ не требуется.";
    } else if (cipherName == "Beaufort") {
        return "Шифр Бофора: использует ключ для вычисления разницы между позициями символов ключа и текста в алфавите. Ключ повторяется до длины текста.";
    } else if (cipherName == "Kuznechik") {
        return "Шифр Кузнечик (упрощённая версия): текст побитово XOR'ится с ключом. Результат кодируется в Base64.";
    } else if (cipherName == "RSA") {
        return "RSA: асимметричный шифр. Текст шифруется публичным ключом с использованием OAEP padding. Результат кодируется в Base64.";
    } else if (cipherName == "AES-256") {
        return "AES-256: симметричный шифр с 256-битным ключом в режиме CBC. Данные дополняются до кратности 16 байт, результат кодируется в Base64.";
    } else if (cipherName == "Blowfish") {
        return "Blowfish: симметричный шифр в режиме CBC. Данные дополняются до кратности 8 байт, результат кодируется в Base64.";
    } else if (cipherName == "3DES") {
        return "3DES: симметричный шифр с тройным применением DES в режиме ECB. Данные дополняются до кратности 8 байт, результат кодируется в Base64.";
    } else if (cipherName == "CAST5") {
        return "CAST5: симметричный шифр в режиме CBC. Данные дополняются до кратности 8 байт, результат кодируется в Base64.";
    }
    return "Неизвестный шифр.";
}

bool Exporter::exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream out(&file);
    out << "Исходный текст:\n" << input << "\n\n";
    out << "Зашифрованный текст:\n" << output << "\n\n";
    out << "Использованный шифр: " << cipherName << "\n";
    out << "Описание шифра:\n" << getCipherDescription(cipherName) << "\n";

    if (!publicKey.isEmpty() && !privateKey.isEmpty()) {
        out << "\nПубличный ключ (для RSA):\n" << publicKey << "\n";
        out << "Приватный ключ (для RSA):\n" << privateKey << "\n";
    }

    file.close();
    return true;
}

bool Exporter::exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName) {
    return exportToFile(filename, input, output, cipherName, QString(), QString());
}

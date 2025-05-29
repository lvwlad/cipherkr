#include "exporter.h"
#include <QFile>
#include <QTextStream>
#include <QJsonObject>
#include <QJsonDocument>

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

bool Exporter::exportToText(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey) {
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

bool Exporter::exportToHtml(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream out(&file);
    out << "<!DOCTYPE html>\n<html>\n<head><title>Результат шифрования</title></head>\n<body>\n";
    out << "<h2>Исходный текст:</h2>\n<p>" << input.toHtmlEscaped() << "</p>\n";
    out << "<h2>Зашифрованный текст:</h2>\n<p>" << output.toHtmlEscaped() << "</p>\n";
    out << "<h2>Использованный шифр:</h2>\n<p>" << cipherName << "</p>\n";
    out << "<h2>Описание шифра:</h2>\n<p>" << getCipherDescription(cipherName).toHtmlEscaped() << "</p>\n";

    if (!publicKey.isEmpty() && !privateKey.isEmpty()) {
        out << "<h2>Ключи (для RSA):</h2>\n";
        out << "<p><strong>Публичный ключ:</strong><br>" << publicKey.toHtmlEscaped() << "</p>\n";
        out << "<p><strong>Приватный ключ:</strong><br>" << privateKey.toHtmlEscaped() << "</p>\n";
    }

    out << "</body>\n</html>";
    file.close();
    return true;
}

bool Exporter::exportToJson(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    QJsonObject jsonObj;
    jsonObj["input_text"] = input;
    jsonObj["encrypted_text"] = output;
    jsonObj["cipher_name"] = cipherName;
    jsonObj["cipher_description"] = getCipherDescription(cipherName);

    if (!publicKey.isEmpty() && !privateKey.isEmpty()) {
        jsonObj["public_key"] = publicKey;
        jsonObj["private_key"] = privateKey;
    }

    QJsonDocument doc(jsonObj);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

bool Exporter::exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey, const QString& format) {
    if (format == "txt") {
        return Exporter::exportToText(filename, input, output, cipherName, publicKey, privateKey);
    } else if (format == "html") {
        return Exporter::exportToHtml(filename, input, output, cipherName, publicKey, privateKey);
    } else if (format == "json") {
        return Exporter::exportToJson(filename, input, output, cipherName, publicKey, privateKey);
    }
    return false;
}

bool Exporter::exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName) {
    return exportToFile(filename, input, output, cipherName, QString(), QString(), "txt");
}

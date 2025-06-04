#include "exporter.h"
#include <QFile>
#include <QTextStream>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime>
#include <QString>

QString Exporter::getCipherDescription(const QString& cipherName) {
    if (cipherName == "Caesar") {
        return QString("Шифр Цезаря: каждый символ текста сдвигается на фиксированное количество позиций в алфавите. Ключ определяет величину сдвига.");
    } else if (cipherName == "Atbash") {
        return QString("Шифр Атбаш: каждый символ заменяется на противоположный в алфавите (например, A на Z, B на Y). Ключ не требуется.");
    } else if (cipherName == "Beaufort") {
        return QString("Шифр Бофора: использует ключ для вычисления разницы между позициями символов ключа и текста в алфавите. Ключ повторяется до длины текста.");
    } else if (cipherName == "Kuznechik") {
        return QString("Шифр Кузнечик: российский стандарт блочного шифрования с размером блока 128 бит и длиной ключа 256 бит.");
    } else if (cipherName == "RSA") {
        return QString("RSA: асимметричный шифр. Текст шифруется публичным ключом с использованием OAEP padding. Результат кодируется в Base64.");
    } else if (cipherName == "AES-256") {
        return QString("AES-256: симметричный шифр с 256-битным ключом в режиме CBC. Данные дополняются до кратности 16 байт, результат кодируется в Base64.");
    } else if (cipherName == "Blowfish") {
        return QString("Blowfish: симметричный шифр в режиме CBC. Данные дополняются до кратности 8 байт, результат кодируется в Base64.");
    } else if (cipherName == "3DES") {
        return QString("3DES: симметричный шифр с тройным применением DES в режиме CBC. Данные дополняются до кратности 8 байт, результат кодируется в Base64.");
    } else if (cipherName == "CAST5") {
        return QString("CAST5: симметричный шифр в режиме CBC. Данные дополняются до кратности 8 байт, результат кодируется в Base64.");
    }
    return QString("Неизвестный шифр.");
}

bool Exporter::exportToText(const QString& filename, const QString& input, const QString& output, const QString& cipherName) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream out(&file);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    out.setCodec("UTF-8");
#endif
    out << "Исходный текст:\n" << input << "\n\n";
    out << "Результат:\n" << output << "\n\n";
    out << "Использованный шифр: " << cipherName << "\n";
    out << "Описание шифра:\n" << getCipherDescription(cipherName) << "\n";

    file.close();
    return true;
}

bool Exporter::exportToHtml(const QString& filename, const QString& input, const QString& output, const QString& cipherName) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream out(&file);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    out.setCodec("UTF-8");
#endif
    out << "<!DOCTYPE html>\n<html>\n<head>\n";
    out << "<meta charset=\"UTF-8\">\n";
    out << "<title>Результат шифрования</title>\n";
    out << "<style>\n";
    out << "body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }\n";
    out << "h1 { color: #2196F3; }\n";
    out << "h2 { color: #1976D2; margin-top: 20px; }\n";
    out << ".content { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
    out << ".text-block { background: #f5f5f5; padding: 15px; border-radius: 4px; margin: 10px 0; }\n";
    out << "</style>\n</head>\n<body>\n";
    out << "<div class=\"content\">\n";
    out << "<h1>Результат шифрования</h1>\n";
    out << "<h2>Исходный текст:</h2>\n<div class=\"text-block\">" << input.toHtmlEscaped() << "</div>\n";
    out << "<h2>Результат:</h2>\n<div class=\"text-block\">" << output.toHtmlEscaped() << "</div>\n";
    out << "<h2>Использованный шифр:</h2>\n<p>" << cipherName.toHtmlEscaped() << "</p>\n";
    out << "<h2>Описание шифра:</h2>\n<p>" << getCipherDescription(cipherName).toHtmlEscaped() << "</p>\n";
    out << "</div>\n</body>\n</html>";

    file.close();
    return true;
}

bool Exporter::exportToJson(const QString& filename, const QString& input, const QString& output, const QString& cipherName) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    QJsonObject jsonObj;
    jsonObj["input_text"] = input;
    jsonObj["output_text"] = output;
    jsonObj["cipher_name"] = cipherName;
    jsonObj["cipher_description"] = getCipherDescription(cipherName);
    jsonObj["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    QJsonDocument doc(jsonObj);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

bool Exporter::exportData(const QString& filename, const QString& format, const QString& input, const QString& output, const QString& cipherName) {
    if (format == "txt") {
        return exportToText(filename, input, output, cipherName);
    } else if (format == "html") {
        return exportToHtml(filename, input, output, cipherName);
    } else if (format == "json") {
        return exportToJson(filename, input, output, cipherName);
    }
    return false;
}

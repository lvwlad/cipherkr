#ifndef EXPORTER_H
#define EXPORTER_H

#include <QString>

class Exporter {
public:
    static bool exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey, const QString& format = "txt");
    static bool exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName);

    static bool exportToText(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey);
    static bool exportToHtml(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey);
    static bool exportToLatex(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey);
};

#endif // EXPORTER_H

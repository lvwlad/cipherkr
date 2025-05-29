#ifndef EXPORTER_H
#define EXPORTER_H

#include <QString>

class Exporter {
public:
    static bool exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName, const QString& publicKey, const QString& privateKey);
    static bool exportToFile(const QString& filename, const QString& input, const QString& output, const QString& cipherName);
};

#endif // EXPORTER_H

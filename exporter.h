#pragma once
#include <QString>

class Exporter {
public:
    static bool exportToFile(const QString& filename,
                             const QString& original,
                             const QString& encrypted,
                             const QString& publicKey = QString(),
                             const QString& privateKey = QString());
};

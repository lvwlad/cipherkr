// Exporter.h
#pragma once
#include <QString>

class Exporter {
public:
    static bool exportToFile(const QString& filename,
                             const QString& original,
                             const QString& encrypted);
};

#pragma once
#include <QString>

QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString rsaEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString rsaDecrypt(const QString& base64Text, const QString& privateKeyPem);

#pragma once
#include <QString>

QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString rsaEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString rsaDecrypt(const QString& base64Text, const QString& privateKeyPem);
QString aes256Encrypt(const QString& text, const QString& key, const QString& alphabet);
QString aes256Decrypt(const QString& base64Text, const QString& key);
QString blowfishEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString blowfishDecrypt(const QString& base64Text, const QString& key);
QString tripleDesEncrypt(const QString& text, const QString& key, const QString& alphabet);
QString tripleDesDecrypt(const QString& base64Text, const QString& key);
QString cast5Encrypt(const QString& text, const QString& key, const QString& alphabet);
QString cast5Decrypt(const QString& base64Text, const QString& key);

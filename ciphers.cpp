#include <QString>

QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    bool ok; int shift = key.toInt(&ok); if (!ok) shift = 0;
    QString result; int n = alphabet.size();
    for (QChar c : text) {
        int idx = alphabet.indexOf(c);
        if (idx >= 0) result.append(alphabet[(idx + shift + n) % n]);
        else result.append(c);
    }
    return result;
}

QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(key);
    QString result; int n = alphabet.size();
    for (QChar c : text) {
        int idx = alphabet.indexOf(c);
        if (idx >= 0) result.append(alphabet[n - 1 - idx]);
        else result.append(c);
    }
    return result;
}

QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    QString result; int n = alphabet.size(); int m = key.size();
    for (int i = 0; i < text.size(); ++i) {
        QChar c = text[i]; int idx = alphabet.indexOf(c);
        if (idx >= 0) {
            int kidx = alphabet.indexOf(key[i % m]);
            result.append(alphabet[(kidx - idx + n) % n]);
        } else result.append(c);
    }
    return result;
}

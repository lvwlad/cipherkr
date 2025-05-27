#include <QString>

// Helper: find index ignoring case and map preserving original case
int indexOfIgnoreCase(const QString& alphabet, QChar c) {
    for (int i = 0; i < alphabet.size(); ++i) {
        if (alphabet[i].toCaseFolded() == c.toCaseFolded())
            return i;
    }
    return -1;
}

QChar adjustCase(QChar resultChar, QChar original) {
    if (original.isLower())
        return resultChar.toLower();
    else
        return resultChar.toUpper();
}

QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    bool ok;
    int shift = key.toInt(&ok);
    if (!ok) shift = 0;
    QString result;
    int n = alphabet.size();
    for (QChar c : text) {
        int idx = indexOfIgnoreCase(alphabet, c);
        if (idx >= 0) {
            int newIdx = (idx + shift % n + n) % n;
            QChar mapped = alphabet[newIdx];
            result.append(adjustCase(mapped, c));
        } else {
            result.append(c);
        }
    }
    return result;
}

QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(key);
    QString result;
    int n = alphabet.size();
    for (QChar c : text) {
        int idx = indexOfIgnoreCase(alphabet, c);
        if (idx >= 0) {
            QChar mapped = alphabet[n - 1 - idx];
            result.append(adjustCase(mapped, c));
        } else {
            result.append(c);
        }
    }
    return result;
}

QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    QString result;
    int n = alphabet.size();
    int m = key.size();
    for (int i = 0; i < text.size(); ++i) {
        QChar c = text[i];
        int idx = indexOfIgnoreCase(alphabet, c);
        if (idx >= 0) {
            QChar keyChar = key[i % m];
            int kidx = indexOfIgnoreCase(alphabet, keyChar);
            if (kidx < 0) {
                result.append(c);
            } else {
                int newIdx = (kidx - idx + n) % n;
                QChar mapped = alphabet[newIdx];
                result.append(adjustCase(mapped, c));
            }
        } else {
            result.append(c);
        }
    }
    return result;
}

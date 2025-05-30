#ifndef EXPORTFORMATDIALOG_H
#define EXPORTFORMATDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QPushButton>

class ExportFormatDialog : public QDialog {
    Q_OBJECT
public:
    explicit ExportFormatDialog(QWidget* parent = nullptr);
    QString getSelectedFormat() const;

private slots:
    void onFormatSelected(const QString& format);

private:
    QString selectedFormat;
    QVBoxLayout* layout;
    QPushButton* txtButton;
    QPushButton* htmlButton;
    QPushButton* jsonButton;
};

#endif // EXPORTFORMATDIALOG_H

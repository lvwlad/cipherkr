#include "exportformatdialog.h"

ExportFormatDialog::ExportFormatDialog(QWidget* parent) : QDialog(parent), selectedFormat("") {
    setWindowTitle("Выберите формат экспорта");

    layout = new QVBoxLayout(this);

    txtButton = new QPushButton("Экспорт в TXT", this);
    htmlButton = new QPushButton("Экспорт в HTML", this);
    jsonButton = new QPushButton("Экспорт в JSON", this);

    layout->addWidget(txtButton);
    layout->addWidget(htmlButton);
    layout->addWidget(jsonButton);

    connect(txtButton, &QPushButton::clicked, this, [this]() { onFormatSelected("txt"); });
    connect(htmlButton, &QPushButton::clicked, this, [this]() { onFormatSelected("html"); });
    connect(jsonButton, &QPushButton::clicked, this, [this]() { onFormatSelected("json"); });

    setLayout(layout);
}

void ExportFormatDialog::onFormatSelected(const QString& format) {
    selectedFormat = format;
    accept();
}

QString ExportFormatDialog::getSelectedFormat() const {
    return selectedFormat;
}

#include <iostream>
#include <QApplication>
#include <QTextStream>
#include <QLineEdit>
#include <QMessageBox>
#include <QWidget>
#include <QPushButton>
#include <QFormLayout>
#include <QProcess>
#include <QFile>
#include <QLabel>
#include <QTimer>
#include <QAnsiTextEdit.h>
#include <QThread>
#include <QListWidget>
#include <QDir>
#include <json.hpp>
#include <QCheckBox>
#include <QMenu>
#include <utility>
#include <QTreeWidget>
#include <QHeaderView>
#include <QTreeWidgetItem>

#include "Manager.hpp"
#include "Parser.hpp"

class AddConfigDialog : public QDialog {
public:
    QTimer *timer;

    explicit AddConfigDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("New config");
        resize(300, 200);

        QFormLayout *layout = new QFormLayout(this);

        QLineEdit *nameEdit = new QLineEdit;
        QLineEdit *typeEdit = new QLineEdit;
        QLineEdit *hostEdit = new QLineEdit;
        QLineEdit *portEdit = new QLineEdit;
        QCheckBox *hasPassword = new QCheckBox;
        QLineEdit *methodEdit = new QLineEdit;
        QLineEdit *passwordEdit = new QLineEdit;

        layout->addRow("Name:", nameEdit);
        layout->addRow("Server:", hostEdit);
        layout->addRow("Port:", portEdit);
        layout->addRow("Type:", typeEdit);
        layout->addRow("Password?", hasPassword);
        layout->addRow("Encryption:", methodEdit);
        layout->addRow("Password:", passwordEdit);

        QPushButton *okButton = new QPushButton("Save");
        layout->addWidget(okButton);

        connect(okButton, &QPushButton::clicked, this, [this, hostEdit, typeEdit, methodEdit, passwordEdit, portEdit, nameEdit]() {
            bool ok =
                !nameEdit->text().toStdString().empty() &&
                !hostEdit->text().toStdString().empty() &&
                !portEdit->text().toStdString().empty();
            ok ? accept() : reject();

            nlohmann::json json = Manager::createJsonConfig(
                typeEdit->text().toStdString(),
                methodEdit->text().toStdString(),
                passwordEdit->text().toStdString(),
                hostEdit->text().toStdString(),
                portEdit->text().toUInt()
            );

            Manager::saveFile(json, nameEdit->text().toStdString());
        });
    }
};

class AddConfigDialog1 : public QDialog {
public:
    QTimer *timer;

    explicit AddConfigDialog1(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Paste proxy");
        resize(300, 100);

        QFormLayout *layout = new QFormLayout(this);

        QTextEdit *proxy = new QTextEdit;
        proxy->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding); // expands with window
        layout->addRow(proxy);

        QPushButton *okButton = new QPushButton("Save");
        layout->addRow(okButton);

        connect(okButton, &QPushButton::clicked, this, [this, proxy]() {
            accept();

            std::vector<std::pair<nlohmann::json, std::string>> proxies = Parser::parse(proxy->toPlainText().toStdString());

            for (std::pair pair : proxies) {
                if (pair.first != nullptr) {
                    std::string server = pair.first["outbounds"][0].value("server", "noname");
                    Logger* logger = Logger::of("dw");
                    logger->info(pair.second.c_str());
                    logger->info(server.c_str());

                    Manager::saveFile(pair.first, server);
                    if (server != "noname") {
                        Manager::addConfigName(server, pair.second);
                    }
                }
            }
        });
    }
};

class SingBoxGUI : public QWidget {
public:
    explicit SingBoxGUI(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("aki-prox");
        resize(800, 500);

        auto *layout = new QFormLayout(this);

        singStatus = new QLabel("sing-box");
        singStatus->setStyleSheet("color: #fc0303;");

        proxyStatus = new QLabel("Proxy");
        proxyStatus->setStyleSheet("color: #fc0303;");

        systemProxyStatus = new QLabel("System proxy");
        systemProxyStatus->setStyleSheet("color: #fc0303;");

        addBtn = new QPushButton("Add");
        settingsBtn = new QPushButton("Settings");

        addBtn->setFixedSize(80, 35);
        settingsBtn->setFixedSize(80, 35);

        QHBoxLayout* upperLayout = new QHBoxLayout;
        QHBoxLayout* statusLayout = new QHBoxLayout;
        QHBoxLayout* upButtonLayout = new QHBoxLayout;

        upperLayout->addLayout(statusLayout);
        upperLayout->addLayout(upButtonLayout);

        upButtonLayout->addWidget(addBtn);
        upButtonLayout->addWidget(settingsBtn);
        upButtonLayout->setSpacing(20);
        upButtonLayout->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        upButtonLayout->setContentsMargins(10, 0, 10, 0);

        statusLayout->addWidget(singStatus);
        statusLayout->addWidget(proxyStatus);
        statusLayout->addWidget(systemProxyStatus);

        statusLayout->setAlignment(Qt::AlignCenter);
        statusLayout->setSpacing(80);

        fileList = new QTreeWidget();
        fileList->setColumnCount(3);
        fileList->setHeaderLabels({"Name", "IP", "Type"});
        fileList->setSelectionMode(QAbstractItemView::SingleSelection);

        fileList->header()->setSectionResizeMode(QHeaderView::ResizeToContents);

        fileList->header()->setSectionsMovable(true);
        fileList->header()->setSectionsClickable(true);

        layout->addRow(upperLayout);

        proxies = new QLabel("Configs:");

        QHBoxLayout* proxiesLayout = new QHBoxLayout;
        proxiesLayout->addWidget(proxies);
        proxiesLayout->setContentsMargins(10, 0, 10, 0);

        layout->addRow(proxiesLayout);
        layout->addRow(fileList);

        connect(fileList, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem *item, int){
            loadProxy(item->data(0, Qt::UserRole).toString().toStdString());
            consoleOutput->appendAnsiText(("Loaded config: " + item->text(0).toStdString()).data());
        });

        QMenu *listMenu = new QMenu;
        QAction *removeAction = listMenu->addAction("Delete");

        fileList->setContextMenuPolicy(Qt::CustomContextMenu);

        fileList->setContextMenuPolicy(Qt::CustomContextMenu);

        QTreeWidgetItem *currentContextItem = nullptr;

        connect(fileList, &QTreeWidget::customContextMenuRequested, this, [this, listMenu, &currentContextItem](const QPoint pos){
            currentContextItem = fileList->itemAt(pos);
            if (currentContextItem) {
                QPoint globalPos = fileList->viewport()->mapToGlobal(pos);
                listMenu->popup(globalPos);
            }
        });

        connect(removeAction, &QAction::triggered, this, [this, &currentContextItem]() {
            if (currentContextItem) {
                std::string name = currentContextItem->data(0, Qt::UserRole).toString().toStdString();
                nlohmann::json names = Manager::getJsonConfig();
                names.erase(name);

                std::ofstream ifs = Manager::getWriteJsonFile();
                ifs << names.dump(4);

                std::string file = "proxies/" + name + ".json";
                delete currentContextItem;

                Logger* logger = Logger::of("removeAction");
                logger->info(file.c_str());

                std::remove(file.c_str());
                currentContextItem = nullptr;
            }
        });

        toggleSingBtn = new QPushButton("Start sing-box.");
        toggleProxyBtn = new QPushButton("Enable proxy.");
        toggleSystemProxyBtn = new QPushButton("Set system proxy.");

        consoleOutput = new QAnsiTextEdit();
        consoleOutput->setReadOnly(true);
        consoleOutput->setMinimumHeight(150);

        QHBoxLayout* buttonLayout = new QHBoxLayout;
        buttonLayout->addWidget(toggleSingBtn);
        buttonLayout->addWidget(toggleProxyBtn);
        buttonLayout->addWidget(toggleSystemProxyBtn);

        layout->addRow(buttonLayout);

        console = new QLabel("Console:");
        clearConsole = new QPushButton("Clear");
        clearConsole->setFixedSize(70, 20);

        QFont font = clearConsole->font();
        font.setPointSize(8);

        clearConsole->setFont(font);

        QHBoxLayout* consoleLayout = new QHBoxLayout;

        consoleLayout->setContentsMargins(10, 0, 10, 0);
        consoleLayout->addWidget(console);
        consoleLayout->addWidget(clearConsole);

        layout->addRow(consoleLayout);
        layout->addRow(consoleOutput);

        QMenu *addMenu = new QMenu;
        QAction *createAction = addMenu->addAction("Create");
        QAction *addAction = addMenu->addAction("Paste");

        connect(addBtn, &QPushButton::clicked, this, [=]() {
            QPoint pos = addBtn->mapToGlobal(QPoint(0, addBtn->height()));
            addMenu->popup(pos);
        });

        connect(createAction, &QAction::triggered, this, &SingBoxGUI::showAddDialog);
        connect(addAction, &QAction::triggered, this, &SingBoxGUI::showAddDialog1);

        connect(toggleSingBtn, &QPushButton::clicked, this, &SingBoxGUI::toggleSing);
        connect(toggleSystemProxyBtn, &QPushButton::clicked, this, &SingBoxGUI::toggleSystemProxy);
        connect(toggleProxyBtn, &QPushButton::clicked, this, &SingBoxGUI::toggleProxy);
        connect(clearConsole, &QPushButton::clicked, this, [=]() {
            consoleOutput->clear();
        });


        timer = new QTimer(this);
        timer->setInterval(2000);
        connect(timer, &QTimer::timeout, this, &SingBoxGUI::timeout);
        timer->start();

        process = new QProcess(this);
        connect(process, &QProcess::readyReadStandardOutput, this, &SingBoxGUI::readProcessOutput);
        connect(process, &QProcess::readyReadStandardError, this, &SingBoxGUI::readProcessError);
        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &SingBoxGUI::processFinished);

        init();
    }

private:
    QLabel *singStatus, *proxyStatus, *systemProxyStatus, *console, *proxies;
    QTimer *timer;
    QAnsiTextEdit *consoleOutput;
    QProcess *process;
    QPushButton *toggleSingBtn, *toggleSystemProxyBtn, *toggleProxyBtn, *clearConsole;
    QPushButton *addBtn, *settingsBtn;
    QTreeWidget *fileList;

    std::string config;

    bool systemProxy;
    const char* proxy;

    void init() {
        std::string path = std::filesystem::current_path().string();
        QProcess::execute("chmod", {"+x", (path + "/scripts/set-vars.sh").c_str()});
        QProcess::execute("chmod", {"+x", (path + "/scripts/unset-vars.sh").c_str()});
        const char* https_proxy = getenv("https_proxy");
        systemProxy = https_proxy == nullptr;
        if (!std::filesystem::exists("config/names.json")) {
            Manager::createConfigNamesFile();
        }
        updateFileList();
    }

    void loadProxy(std::string filename) {
        config = std::move(filename);

        QProcess pgrep;
        pgrep.start("pgrep", {"sing-box"});

        pgrep.waitForFinished();

        QString pid = QString(pgrep.readAllStandardOutput()).trimmed();

        if (!pid.isEmpty()) reloadSing();
    }

    static void updateList(QListWidget *fileList, QList<QPair<QString, QString>> pairs) {
        nlohmann::json json = Manager::getJsonConfig();

        fileList->clear();

        for (QPair pair : pairs) {
            QListWidgetItem* item = new QListWidgetItem(pair.first);
            item->setData(Qt::UserRole, pair.second);
            fileList->addItem(item);
        }

        Logger* logger = Logger::of("WD");
        //logger->info(parsed.size());
    }

    void updateFileList() {
        QDir dir("proxies");
        QStringList files = dir.entryList(QDir::Files);

        fileList->clear();
        nlohmann::json config = Manager::getJsonConfig();

        for (QString &file : files) {
            file = QFileInfo(file).completeBaseName();
            std::string fname = file.toStdString();

            // Чтение JSON из файла
            std::ifstream ifs(("proxies/" + fname + ".json").c_str());
            nlohmann::json json;
            ifs >> json;

            // Берем сервер и тип из первого outbounds
            std::string server = "unknown";
            std::string type = "unknown";

            if (!json["outbounds"].empty()) {
                server = json["outbounds"][0].value("server", "unknown");
                type = json["outbounds"][0].value("type", "unknown");
            }

            // Имя — просто имя файла
            auto name = config.value(server, server);

            QTreeWidgetItem* item = new QTreeWidgetItem({
                QString::fromStdString(name),
                QString::fromStdString(server),
                QString::fromStdString(type)
            });
            item->setData(0, Qt::UserRole, QString::fromStdString(fname)); // хранение имени файла
            fileList->addTopLevelItem(item);
        }
    }


    void toggleProxy() {
        if (process->state() != QProcess::NotRunning) {
            process->terminate();
            if (!process->waitForFinished(1000)) {
                process->kill();
                process->waitForFinished();
            }
        }
    }

    void toggleSystemProxy() {
        std::string path = std::filesystem::current_path().string();
        std::string script = systemProxy ? "/scripts/set-vars.sh" : "/scripts/unset-vars.sh";

        QProcess::execute("bash", { (path + script).c_str() });
        systemProxy = !systemProxy;
    }

    void reloadSing() {
        QProcess pgrep;
        pgrep.start("pgrep", {"sing-box"});
        pgrep.waitForFinished();

        QString pid = QString(pgrep.readAllStandardOutput()).trimmed();
        if (!pid.isEmpty()) {
            QProcess::execute("kill", {pid});
            process->start("sing-box", {"run", "-c", ("proxies/" + config + ".json").c_str()});
            if (!process->waitForStarted(3000)) {
                QMessageBox::critical(this, "Error", "Failed to reload sing-box service");
            }
        }
    }

    void toggleSing() {
        QProcess pgrep;
        pgrep.start("pgrep", {"sing-box"});
        pgrep.waitForFinished();

        QString pid = QString(pgrep.readAllStandardOutput()).trimmed();
        if (!pid.isEmpty()) {
            QProcess::execute("kill", {pid});
        } else {
            process->start("sing-box", {"run", "-c", ("proxies/" + config + ".json").c_str()});
            if (!process->waitForStarted(3000)) {
                QMessageBox::critical(this, "Error", "Failed to start sing-box service");
            }
        }
    }

    void readProcessOutput() {
        QByteArray output = process->readAllStandardOutput();
        consoleOutput->appendAnsiText(QString::fromLocal8Bit(output));
    }

    void readProcessError() {
        QByteArray error = process->readAllStandardError();
        consoleOutput->appendAnsiText(QString::fromLocal8Bit(error));
    }

    void processFinished(int exitCode, QProcess::ExitStatus exitStatus) {
        Q_UNUSED(exitCode);
        Q_UNUSED(exitStatus);
        consoleOutput->appendAnsiText("sing-box service stopped.");
    }

    void timeout() {
        updateFileList();

        if (process->state() == QProcess::NotRunning) {
            singStatus->setText("sing-box");
            singStatus->setStyleSheet("color: #fc0303;");
            toggleSingBtn->setText("Start sing-box.");
        } else {
            singStatus->setText("sing-box");
            singStatus->setStyleSheet("color: #0bfc03;");
            toggleSingBtn->setText("Stop sing-box.");
        }

        if (systemProxy) {
            systemProxyStatus->setText("System proxy");
            systemProxyStatus->setStyleSheet("color: #fc0303;");
            toggleSystemProxyBtn->setText("Set system proxy.");
        } else {
            systemProxyStatus->setText("System proxy");
            systemProxyStatus->setStyleSheet("color: #0bfc03;");
            toggleSystemProxyBtn->setText("Clear system proxy.");
        }

        proxyStatus->setText("Proxy");
        proxyStatus->setStyleSheet(process->state() == QProcess::Running ? "color: #0bfc03;" : "color: #fc0303;");
        toggleProxyBtn->setText(process->state() == QProcess::Running ? "Disable proxy." : "Enable proxy.");
    }

    void showAddDialog() {
        AddConfigDialog dialog(this);
        if (dialog.exec() == QDialog::Accepted) {
            QMessageBox::information(this, "Notification", "Configuration added.");
        } else {
            QMessageBox::warning(this, "Notification", "Configuration not added.");
        }
    }

    void showAddDialog1() {
        AddConfigDialog1 dialog(this);
        if (dialog.exec() == QDialog::Accepted) {
            QMessageBox::information(this, "Notification", "Configuration added.");
        }
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    SingBoxGUI gui;
    gui.show();
    return app.exec();
}

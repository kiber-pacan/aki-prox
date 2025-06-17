#include <iostream>
#include <QApplication>
#include <QTextStream>
#include <QLineEdit>
#include <QMessageBox>

#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QFormLayout>
#include <QProcess>
#include <QFile>
#include <QLabel>
#include <QTimer>
#include <QAnsiTextEdit.h>
#include <json.hpp>

class SingBoxGUI : public QWidget {
public:
    explicit SingBoxGUI(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("aki-prox");
        resize(800, 500);

        auto *layout = new QFormLayout(this);

        status = new QLabel("sing-box неактивен.");

        ipEdit = new QLineEdit("150.241.69.126");
        portEdit = new QLineEdit("3452");
        methodEdit = new QLineEdit("chacha20-ietf-poly1305");
        passwordEdit = new QLineEdit("OX76ndgTcyESeUnZe0r5dO");
        passwordEdit->setEchoMode(QLineEdit::Password);

        timer = new QTimer(this);
        timer->setInterval(250);

        toggleSingBtn = new QPushButton("Запустить sing-box");
        toggleSystemProxyBtn = new QPushButton("Установить системный прокси");
        toggleProxyBtn = new QPushButton("Включить прокси");

        consoleOutput = new QAnsiTextEdit();
        consoleOutput->setReadOnly(true);
        consoleOutput->setMinimumHeight(150);

        layout->addRow(status);
        layout->addRow("IP сервера:", ipEdit);
        layout->addRow("Порт:", portEdit);
        layout->addRow("Метод:", methodEdit);
        layout->addRow("Пароль:", passwordEdit);

        QHBoxLayout* buttonLayout = new QHBoxLayout;
        buttonLayout->addWidget(toggleSingBtn);
        buttonLayout->addWidget(toggleSystemProxyBtn);
        buttonLayout->addWidget(toggleProxyBtn);


        layout->addRow(buttonLayout);
        layout->addRow("Вывод консоли:", consoleOutput);

        connect(toggleSingBtn, &QPushButton::clicked, this, &SingBoxGUI::toggleSing);
        connect(toggleSystemProxyBtn, &QPushButton::clicked, this, &SingBoxGUI::toggleSystemProxy);
        connect(toggleProxyBtn, &QPushButton::clicked, this, &SingBoxGUI::toggleProxy);

        connect(timer, &QTimer::timeout, this, &SingBoxGUI::timeout);
        timer->start();

        process = new QProcess(this);
        connect(process, &QProcess::readyReadStandardOutput, this, &SingBoxGUI::readProcessOutput);
        connect(process, &QProcess::readyReadStandardError, this, &SingBoxGUI::readProcessError);
        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &SingBoxGUI::processFinished);

        init();
    }

    nlohmann::json proxyOff = {
        { "log", {
                { "level", "info" },
                { "output", "stderr" }
        }}
    };

private:
    QLineEdit *ipEdit, *portEdit, *methodEdit, *passwordEdit;
    QLabel *status;
    QTimer *timer;
    QAnsiTextEdit *consoleOutput;
    QProcess *process;

    QPushButton *toggleSingBtn, *toggleSystemProxyBtn, *toggleProxyBtn;

    bool systemProxy;

    nlohmann::json config;

    nlohmann::json getConfig() {
        return {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", "shadowsocks" },
                { "server", ipEdit->text().toStdString() },
                { "server_port", portEdit->text().toInt() },
                { "method", methodEdit->text().toStdString() },
                { "password", passwordEdit->text().toStdString() }
            }}}
        };
    }

    void init() {
        QProcess::execute("chmod", {"+x", PROJECT_ROOT_DIR "/proxy/set-vars-fish.sh"});
        QProcess::execute("chmod", {"+x", PROJECT_ROOT_DIR "/proxy/unset-vars-fish.sh"});

        const char* https_proxy = getenv("https_proxy");

        systemProxy = https_proxy == nullptr;
    }

    void toggleProxy() {
        if (config == proxyOff) {
            config = getConfig();
        } else {
            config = proxyOff;
        }
    }

    void toggleSystemProxy() {
        const char* https_proxy = getenv("https_proxy");
        systemProxy = !systemProxy;

        if (https_proxy == nullptr) {
            QProcess::execute(PROJECT_ROOT_DIR "/proxy/set-vars-fish.sh");
        } else {
            QProcess::execute(PROJECT_ROOT_DIR "/proxy/unset-vars-fish.sh");
        }
    }

    void toggleSing() {
        QProcess pgrep;
        pgrep.start("pgrep", {"sing-box"});
        pgrep.waitForFinished();

        QString pid = QString(pgrep.readAllStandardOutput()).trimmed();

        if (!pid.isEmpty()) {
            stopSingBox(pid);
        } else {
            startSingBox(pid);
        }
    }

    void startSingBox(const QString& pid) {
        config = getConfig();

        loadFile();

        if (!pid.isEmpty()) {
            QMessageBox::information(nullptr, "Информация", "sing-box уже запущен, перезапускаем процесс.");
            QProcess::execute("kill", {pid});
        }

        // Запускаем sing-box
        #ifdef Q_OS_WIN
                process->setProgram("sing-box.exe");
        #else
                process->setProgram("sing-box");
        #endif
                process->setArguments({"run", "-c", "config.json"});

        consoleOutput->appendAnsiText("Запуск sing-box...");

        process->start();
        if (!process->waitForStarted()) {
            QMessageBox::critical(this, "Ошибка", "Не удалось запустить sing-box");
            consoleOutput->appendAnsiText("Ошибка запуска sing-box!");
        }
    }

    void stopSingBox(const QString& pid) const {
        if (!pid.isEmpty()) {
            QProcess::execute("kill", {pid});
        } else {
            consoleOutput->appendAnsiText("sing-box не запущен.");
        }
    }

    void loadFile() {
        QFile file("config.json");
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::critical(this, "Ошибка", "Не удалось создать config.json");
            return;
        }

        QTextStream out(&file);

        out << QString::fromStdString(config.dump(4));
        file.close();
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
        consoleOutput->appendAnsiText("sing-box процесс завершён.");
    }

    void timeout() {
        if (process->state() == QProcess::NotRunning) {
            status->setText("sing-box неактивен!");
            toggleSingBtn->setText("Запустить sing-box");

        } else if (process->state() == QProcess::Running) {
            status->setText("sing-box активен!");
            toggleSingBtn->setText("Отключить sing-box");
        }

        if (systemProxy) {
            toggleSystemProxyBtn->setText("Установить системный прокси.");
        } else {
            toggleSystemProxyBtn->setText("Очистить системный прокси.");
        }
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    SingBoxGUI gui;
    gui.show();
    return app.exec();
}

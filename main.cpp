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
#include <QThread>

class SingBoxGUI : public QWidget {
public:
    explicit SingBoxGUI(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("aki-prox");
        resize(800, 500);

        auto *layout = new QFormLayout(this);

        QHBoxLayout* statusLayout = new QHBoxLayout;

        singStatus = new QLabel("sing-box неактивен.");
        proxyStatus = new QLabel("Прокси неактивен.");
        systemProxyStatus = new QLabel("Системный прокси не установлен.");

        statusLayout->addWidget(singStatus);
        statusLayout->addWidget(proxyStatus);
        statusLayout->addWidget(systemProxyStatus);

        statusLayout->setAlignment(Qt::AlignCenter);
        statusLayout->setSpacing(80);

        ipEdit = new QLineEdit("150.241.69.126");
        portEdit = new QLineEdit("3452");
        methodEdit = new QLineEdit("chacha20-ietf-poly1305");
        passwordEdit = new QLineEdit("OX76ndgTcyESeUnZe0r5dO");
        passwordEdit->setEchoMode(QLineEdit::Password);

        timer = new QTimer(this);
        timer->setInterval(75);

        toggleSingBtn = new QPushButton("Запустить sing-box.");
        toggleProxyBtn = new QPushButton("Включить прокси.");
        toggleSystemProxyBtn = new QPushButton("Установить системный прокси.");

        consoleOutput = new QAnsiTextEdit();
        consoleOutput->setReadOnly(true);
        consoleOutput->setMinimumHeight(150);

        layout->addRow(statusLayout);
        layout->addRow("IP сервера:", ipEdit);
        layout->addRow("Порт:", portEdit);
        layout->addRow("Метод:", methodEdit);
        layout->addRow("Пароль:", passwordEdit);

        QHBoxLayout* buttonLayout = new QHBoxLayout;
        buttonLayout->addWidget(toggleSingBtn);
        buttonLayout->addWidget(toggleProxyBtn);
        buttonLayout->addWidget(toggleSystemProxyBtn);


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

    ~SingBoxGUI() {
        runScript("bash", unsetPath.data());
        if (process && process->state() != QProcess::NotRunning) {
            process->terminate();
            if (!process->waitForFinished(3000)) {
                process->kill();
                process->waitForFinished();
            }
        }
    }

    nlohmann::json proxyOff = {
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
            { "type", "direct" },
            { "tag", "direct-out" }
        }}},
        { "route", {
            { "rules", {{
                { "type", "default" },
                { "outbound", "direct-out" }
            }}}
        }}
    };

    std::string path = std::filesystem::current_path().string();
    std::string setPath = path + "/scripts/set-vars.sh";
    std::string unsetPath = path + "/scripts/unset-vars.sh";

private:
    QLineEdit *ipEdit, *portEdit, *methodEdit, *passwordEdit;
    QLabel *singStatus, *proxyStatus, *systemProxyStatus;
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

    static bool runScript(const QString& shellPath, const QString& scriptPath, const QStringList& arguments = {}) {
        QProcess process;

        QStringList args = {scriptPath};
        args.append(arguments);

        process.start(shellPath, args);

        if (!process.waitForStarted(3000)) {
            qWarning() << "Не удалось запустить процесс";
            return false;
        }

        process.waitForFinished();

        QString output = process.readAllStandardOutput();
        QString error = process.readAllStandardError();

        qDebug() << "[STDOUT]" << output.trimmed();
        if (!error.isEmpty()) qWarning() << "[STDERR]" << error.trimmed();

        int exitCode = process.exitCode();
        if (exitCode != 0) {
            qWarning() << "Скрипт завершился с ошибкой, код:" << exitCode;
            return false;
        }

        return true;
    }


    void init() {
        const char* setProxy = setPath.c_str();
        const char* unSetProxy = unsetPath.c_str();

        QProcess::execute("chmod", {"+x", setProxy});
        QProcess::execute("chmod", {"+x", unSetProxy});

        const char* https_proxy = getenv("https_proxy");

        qDebug() << "https_proxy:" << https_proxy;
        
        systemProxy = https_proxy == nullptr;
    }

    void toggle(const QString& pid) {
        config = config == proxyOff ? getConfig() : proxyOff;

        loadFile(config);
        startSingBoxProcess(pid);
    }

    void toggleProxy() {
        if (process->state() != QProcess::NotRunning) {
            process->terminate();

            if (!process->waitForFinished(1000)) {
                process->kill();
                process->waitForFinished();
            }

            toggle(nullptr);  // Всегда вызываем toggle() после завершения
        }
    }


    void toggleSystemProxy() {
        //process->setWorkingDirectory(path.data());

        if (systemProxy) {
            runScript("bash", setPath.data());
        } else {
            runScript("bash", unsetPath.data());
        }

        systemProxy = !systemProxy;
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

    void startSingBoxProcess(const QString& pid) {
        if (!pid.isEmpty()) {
            QMessageBox::information(nullptr, "Информация", "sing-box уже запущен, перезапускаем процесс.");
            //QProcess::execute("kill", {pid});
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
        if (!process->waitForStarted(3000)) {
            QMessageBox::critical(this, "Ошибка", "Не удалось запустить sing-box");
            consoleOutput->appendAnsiText("Ошибка запуска sing-box!");
        }
    }


    void startSingBox(const QString& pid) {
        config = getConfig();

        loadFile(config);

        startSingBoxProcess(pid);
    }

    void stopSingBox(const QString& pid) const {
        if (!pid.isEmpty()) {
            QProcess::execute("kill", {pid});
        } else {
            consoleOutput->appendAnsiText("sing-box не запущен.");
        }
    }

    void loadFile(const nlohmann::json& config) {
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
            singStatus->setText("sing-box неактивен.");
            singStatus->setStyleSheet("color: #fc0303;");

            toggleSingBtn->setText("Запустить sing-box.");

        } else if (process->state() == QProcess::Running) {
            singStatus->setText("sing-box активен!");
            singStatus->setStyleSheet("color: #0bfc03;");

            toggleSingBtn->setText("Отключить sing-box.");
        }

        if (systemProxy) {
            systemProxyStatus->setText("Системный прокси неактивен.");
            systemProxyStatus->setStyleSheet("color: #fc0303;");

            toggleSystemProxyBtn->setText("Установить системный прокси.");
        } else {
            systemProxyStatus->setText("Системный прокси активен!");
            systemProxyStatus->setStyleSheet("color: #0bfc03;");

            toggleSystemProxyBtn->setText("Очистить системный прокси.");
        }

        if (config == proxyOff || process->state() == QProcess::NotRunning) {
            proxyStatus->setText("Прокси неактивен.");
            proxyStatus->setStyleSheet("color: #fc0303;");

            toggleProxyBtn->setText("Включить прокси.");
        } else if (process->state() == QProcess::Running) {
            proxyStatus->setText("Прокси активен!");
            proxyStatus->setStyleSheet("color: #0bfc03;");

            toggleProxyBtn->setText("Отключить прокси.");
        }
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    SingBoxGUI gui;
    gui.show();
    return app.exec();
}

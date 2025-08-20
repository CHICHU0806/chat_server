// chat_server.cpp

#include "chat_server.h" // 包含自己的头文件
#include <QHostAddress>    // 用于绑定IP地址
#include <QDebug>          // 用于在命令行输出调试和信息
#include <QJsonDocument>   // 用于解析JSON
#include <QJsonObject>     // 用于解析JSON
#include <QSqlError>       // 确保包含
#include <QDir>            // 用于处理文件路径和目录创建
#include <QCoreApplication> // 用于获取应用程序路径

// 构造函数：初始化成员变量，连接信号和槽
ChatServer::ChatServer(QObject *parent)
    : QObject(parent),
      m_tcpServer(new QTcpServer(this)) // 初始化 m_tcpServer
{
    // **数据库连接设置**
    m_db = QSqlDatabase::addDatabase("QSQLITE"); // 添加 SQLite 驱动

    // 获取应用程序可执行文件所在的目录
    QString appDirPath = QCoreApplication::applicationDirPath();

    // 构建数据库文件路径：假设数据库在项目根目录下的 Database 文件夹中
    // 从可执行文件目录向上导航一级 (..)，再进入 Database 文件夹
    QString databaseFolderPath = QDir::cleanPath(appDirPath + QDir::separator() + ".." + QDir::separator() + "Database");

    QDir dir(databaseFolderPath);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) { // 尝试创建目录
            qCritical() << "服务器无法创建指定的数据库目录：" << databaseFolderPath;
        } else {
            qInfo() << "已创建指定的服务器数据库目录：" << databaseFolderPath;
        }
    }

    QString dbPath = databaseFolderPath + QDir::separator() + "user_data.db";
    m_db.setDatabaseName(dbPath);

    if (!m_db.open()) {
        qCritical() << "服务器数据库连接失败：" << m_db.lastError().text();
    } else {
        qInfo() << "服务器数据库连接成功，文件：" << dbPath;

        QSqlQuery query(m_db);
        QString createTableSql = "CREATE TABLE IF NOT EXISTS Users ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                 "username TEXT UNIQUE NOT NULL,"
                                 "account TEXT UNIQUE NOT NULL,"
                                 "password TEXT NOT NULL"
                                 ");";
        if (!query.exec(createTableSql)) {
            qCritical() << "服务器无法创建 Users 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 Users 表已准备好。";
        }
    }
    //数据库设置结束

    // 将 m_tcpServer 发出的 newConnection() 信号连接到 ChatServer 的 onNewConnection() 槽函数
    connect(m_tcpServer, &QTcpServer::newConnection, this, &ChatServer::onNewConnection);
    qInfo() << "ChatServer initialized.";
}

// 析构函数：清理资源
ChatServer::~ChatServer() {
    stopServer(); // 确保在 ChatServer 对象销毁前，服务器已经停止监听
    if (m_db.isOpen()) {
        m_db.close();
        qInfo() << "服务器数据库已关闭。";
    }
    qInfo() << "ChatServer destroyed.";
}

// 启动服务器监听
bool ChatServer::startServer(quint16 port) {
    if (!m_tcpServer->listen(QHostAddress::Any, port)) {
        qCritical() << "无法启动服务器：" << m_tcpServer->errorString();
        return false;
    }
    qInfo() << "服务器正在监听端口" << port;
    qInfo() << "聊天服务器已在端口" << port << "上启动。等待客户端连接...";
    return true;
}

// 停止服务器监听
void ChatServer::stopServer() {
    if (m_tcpServer->isListening()) {
        m_tcpServer->close(); // 关闭监听套接字
        qInfo() << "服务器停止监听。";
    }

    // 遍历所有已连接的客户端套接字，并进行清理
    QList<QTcpSocket*> clientSocketsToClose = m_clientBlockSizes.keys();
    qInfo() << "正在关闭所有 " << clientSocketsToClose.size() << " 个活跃客户端连接...";

    for (QTcpSocket* clientSocket : clientSocketsToClose) {
        if (clientSocket->state() == QAbstractSocket::ConnectedState) {
            clientSocket->disconnectFromHost(); // 向客户端发送断开连接请求
            // 这里不立即 deleteLater()，依赖 onDisconnected() 槽来安全清理
        }
    }
    // 理论上所有客户端都会触发 onDisconnected，导致 m_clientBlockSizes 被清空
    // 但为保险起见，可以在这里显式清空一次，或者只依赖 onDisconnected
    m_clientBlockSizes.clear(); // 清空 QHash
    qInfo() << "所有客户端连接清理完毕。";
}

// 槽函数：处理新的客户端连接
void ChatServer::onNewConnection() {
    QTcpSocket* newClientSocket = m_tcpServer->nextPendingConnection();
    if (!newClientSocket) {
        qCritical() << "服务器获取新的客户端连接失败！";
        return;
    }

    m_clientBlockSizes.insert(newClientSocket, 0); // 初始化为0，表示等待读取新数据包的长度

    connect(newClientSocket, &QTcpSocket::readyRead, this, &ChatServer::onReadyRead);
    connect(newClientSocket, &QTcpSocket::disconnected, this, &ChatServer::onDisconnected);
    connect(newClientSocket, &QTcpSocket::errorOccurred, this, &ChatServer::onErrorOccurred);

    qInfo() << "新连接来自：" << getPeerInfo(newClientSocket) << "。当前在线客户端数量：" << m_clientBlockSizes.size();
}

// 槽函数：当当前客户端套接字有数据可读时被调用 (修正版)
void ChatServer::onReadyRead() {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onReadyRead: 无法获取发送信号的套接字！";
        return;
    }

    QDataStream in(senderSocket);
    in.setVersion(QDataStream::Qt_6_0);

    quint32 currentBlockSize = m_clientBlockSizes.value(senderSocket);

    for (;;) {
        if (currentBlockSize == 0) {
            if (senderSocket->bytesAvailable() < (qint64)sizeof(quint32)) {
                return; // 数据不足以读取完整的数据包长度，等待更多数据
            }
            in >> currentBlockSize;
            qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): 读取到数据包的预期总长度 (currentBlockSize):" << currentBlockSize;
            m_clientBlockSizes[senderSocket] = currentBlockSize;
        }

        if (senderSocket->bytesAvailable() < currentBlockSize) {
            return; // 数据不足以读取完整的数据包，等待更多数据
        }

        QByteArray jsonData;
        in >> jsonData;

        qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): QDataStream 成功读取到 JSON 数据块。大小:" << jsonData.size();
        qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): 原始 JSON 数据 (Hex):" << jsonData.toHex();
        qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): 原始 JSON 数据 (UTF8):" << QString::fromUtf8(jsonData);

        QJsonDocument doc = QJsonDocument::fromJson(jsonData);
        if (doc.isNull() || !doc.isObject()) {
            qWarning() << "无法解析传入的 JSON 数据来自 " << getPeerInfo(senderSocket) << "。原始数据 (Hex):" << jsonData.toHex();
            sendErrorResponse(senderSocket, "无效的请求格式。", "unknown"); // 使用辅助函数发送错误响应
            m_clientBlockSizes[senderSocket] = 0;
            break;
        }

        QJsonObject request = doc.object();
        QString requestType = request["type"].toString();
        QString account = request["account"].toString();
        QString password = request["password"].toString();

        qInfo() << "成功解析请求来自 " << getPeerInfo(senderSocket) << "：类型=" << requestType << ", 账号=" << account << ", 密码=" << password;

        // **核心修正：使用明确的 else if 结构来处理不同类型的请求**
        if (requestType == "register") {
            QString username = request["username"].toString();
            handleRegisterRequest(senderSocket, username, account, password);
        } else if (requestType == "login") {
            handleLoginRequest(senderSocket, account, password);
        } else if (requestType == "chatMessage") {QString messageType = request["messageType"].toString(); // 获取消息类型
            QString targetAccount = request["targetAccount"].toString(); // 获取目标账号（私聊时使用）

            if (messageType == "private") {
                handlePrivateChatMessage(senderSocket, account, request["content"].toString(), targetAccount);
            } else if (messageType == "public"){
                handleChatMessage(senderSocket, account, request["content"].toString());
            }
        }
        else if (requestType == "updateUserInfo") {
            QString nickname = request["nickname"].toString();
            QString oldPassword = request["oldPassword"].toString();
            QString newPassword = request["newPassword"].toString();
            handleUpdateUserInfo(senderSocket, account, nickname, oldPassword, newPassword);
        }
        else {
            // 未知的请求类型
            QString errorMessage = "服务器无法处理该请求类型：" + requestType;
            qWarning() << "服务器收到未知请求类型来自 " << getPeerInfo(senderSocket) << "：" << requestType;
            sendErrorResponse(senderSocket, errorMessage, requestType); // 使用辅助函数发送错误响应
        }

        m_clientBlockSizes[senderSocket] = 0; // 处理完一个完整的数据包后，重置该客户端的 m_blockSize
    }
}


// 槽函数：当当前客户端套接字断开连接时被调用
void ChatServer::onDisconnected() {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onDisconnected: 无法获取发送信号的套接字！";
        return;
    }

    qInfo() << "客户端 [" << getPeerInfo(senderSocket) << "] 已断开连接。";

    if (m_clientBlockSizes.contains(senderSocket)) {
        m_clientBlockSizes.remove(senderSocket);
        qInfo() << "已从客户端列表中移除 [" << getPeerInfo(senderSocket) << "]。当前在线客户端数量：" << m_clientBlockSizes.size();
    } else {
        qWarning() << "onDisconnected: 尝试移除一个不在列表中的套接字！[" << getPeerInfo(senderSocket) << "]";
    }

    senderSocket->deleteLater(); // 安全地删除 QTcpSocket 对象。
}

// 槽函数：处理套接字发生的错误
void ChatServer::onErrorOccurred(QAbstractSocket::SocketError socketError) {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onErrorOccurred: 无法获取发送信号的套接字！";
        return;
    }

    qCritical() << "客户端 [" << getPeerInfo(senderSocket) << "] 发生套接字错误："
                << senderSocket->errorString() << " (错误码：" << socketError << ")";
}


// **辅助函数：获取客户端的 IP:Port 信息**
QString ChatServer::getPeerInfo(QTcpSocket* socket) const {
    if (socket) {
        return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
    }
    return "未知客户端";
}

// **辅助函数：发送通用的 JSON 响应**
void ChatServer::sendResponse(QTcpSocket *socket, const QJsonObject &response) {
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        qWarning() << "sendResponse: 套接字未连接或无效，无法发送响应。";
        return;
    }

    QByteArray jsonData = QJsonDocument(response).toJson(QJsonDocument::Compact);
    QByteArray dataBlock;
    QDataStream out(&dataBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << (quint32)0; // 预留总长度位置
    out << jsonData;   // 写入实际 JSON 数据

    out.device()->seek(0);
    out << (quint32)(dataBlock.size() - sizeof(quint32)); // 写入真正的总长度

    qDebug() << "DEBUG (Server to " << getPeerInfo(socket) << "): 发送响应数据包总大小:" << dataBlock.size();
    qDebug() << "DEBUG (Server to " << getPeerInfo(socket) << "): outer quint32 value being written:" << (quint32)(dataBlock.size() - sizeof(quint32));
    qDebug() << "DEBUG (Server to " << getPeerInfo(socket) << "): 发送响应数据包内容 (Hex):" << dataBlock.toHex();

    socket->write(dataBlock);
    socket->flush();
}

// **辅助函数：发送错误响应**
void ChatServer::sendErrorResponse(QTcpSocket *socket, const QString &message, const QString &requestType) {
    QJsonObject response;
    response["type"] = requestType; // 错误响应也带上原请求类型，方便客户端识别
    response["status"] = "error";
    response["message"] = message;
    sendResponse(socket, response);
    qInfo() << "已发送错误响应给 [" << getPeerInfo(socket) << "] (类型: " << requestType << "): " << message;
}

// **辅助函数：处理注册请求的逻辑**
void ChatServer::handleRegisterRequest(QTcpSocket* socket, const QString& username, const QString& account, const QString& password) {
    QJsonObject response;
    response["type"] = "register";

    // 验证输入数据
    if (account.isEmpty() || password.isEmpty() || username.isEmpty()) {
        response["status"] = "error";
        response["message"] = "注册失败：账号、密码和昵称不能为空。";
        sendResponse(socket, response);
        qWarning() << "注册失败：输入数据不完整";
        return;
    }

    //检查昵称是否重复
    QSqlQuery checkUsernameQuery(m_db);
    checkUsernameQuery.prepare("SELECT username FROM Users WHERE username = :username");
    checkUsernameQuery.bindValue(":username", username);

    if (checkUsernameQuery.exec() && checkUsernameQuery.next()) {
        response["status"] = "error";
        response["message"] = "注册失败：昵称 '" + username + "' 已存在。";
        sendResponse(socket, response);
        qWarning() << "注册失败：昵称重复：" << username;
        return;
    }

    //检查账号是否重复
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT account FROM Users WHERE account = :account");
    checkQuery.bindValue(":account", account);

    if (checkQuery.exec() && checkQuery.next()) {
        response["status"] = "error";
        response["message"] = "注册失败：账号 '" + account + "' 已存在。";
        qWarning() << "注册失败：账号重复：" << account;
    } else {
        QSqlQuery insertQuery(m_db);
        insertQuery.prepare("INSERT INTO Users (username, account, password) VALUES (:username, :account, :password)");
        insertQuery.bindValue(":username", username);
        insertQuery.bindValue(":account", account);
        insertQuery.bindValue(":password", password);

        if (insertQuery.exec()) {
            response["status"] = "success";
            response["message"] = "注册成功！欢迎 " + username + "！";
            response["username"] = username;
            qInfo() << "新用户注册成功：账号=" << account << ", 昵称=" << username;
        } else {
            response["status"] = "error";
            response["message"] = "注册失败：数据库错误 - " + insertQuery.lastError().text();
            qCritical() << "注册失败：数据库错误：" << insertQuery.lastError().text();
        }
    }
    sendResponse(socket, response);
    qInfo() << "已发送注册响应给 [" << getPeerInfo(socket) << "]";
}

// **辅助函数：处理登录请求的逻辑**
void ChatServer::handleLoginRequest(QTcpSocket* socket, const QString& account, const QString& password) {
    QJsonObject response;
    response["type"] = "login";

    QSqlQuery query(m_db);
    query.prepare("SELECT username FROM Users WHERE account = :account AND password = :password");
    query.bindValue(":account", account);
    query.bindValue(":password", password);

    if (query.exec() && query.next()) {
        QString username = query.value("username").toString();
        response["status"] = "success";
        response["message"] = "登录成功！欢迎 " + username + "！";
        response["username"] = username;
        qInfo() << "用户登录成功：账号=" << account << ", 昵称=" << username << " from " << getPeerInfo(socket);
    } else {
        response["status"] = "error";
        response["message"] = "登录失败：账号或密码不正确。";
        qWarning() << "用户登录失败：账号=" << account << ", 密码=" << password << " from " << getPeerInfo(socket);
    }
    sendResponse(socket, response);
    qInfo() << "已发送登录响应给 [" << getPeerInfo(socket) << "]";
}

// **辅助函数：处理聊天消息请求的逻辑**
void ChatServer::handleChatMessage(QTcpSocket* socket, const QString& account, const QString& content) {
    // 验证输入数据
    if (account.isEmpty() || content.isEmpty()) {
        QJsonObject response;
        response["type"] = "chatMessage";
        response["status"] = "error";
        response["message"] = "聊天消息发送失败：账号和消息内容不能为空。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "聊天消息发送失败：输入数据不完整";
        return;
    }

    // 验证用户是否存在
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    checkQuery.bindValue(":account", account);

    if (!checkQuery.exec() || !checkQuery.next()) {
        QJsonObject response;
        response["type"] = "chatMessage";
        response["status"] = "error";
        response["message"] = "聊天消息发送失败：用户不存在。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "聊天消息发送失败：用户不存在：" << account;
        return;
    }

    QString username = checkQuery.value("username").toString();
    qInfo() << "收到聊天消息：来自用户" << username << "(" << account << ")的消息：" << content;

    // 构建广播消息
    QJsonObject broadcastMessage;
    broadcastMessage["type"] = "chatMessage";
    broadcastMessage["status"] = "broadcast";
    broadcastMessage["sender"] = account;
    broadcastMessage["username"] = username;
    broadcastMessage["content"] = content;
    broadcastMessage["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 向所有在线客户端广播消息（包括发送者）
    int broadcastCount = 0;
    for (auto it = m_clientBlockSizes.begin(); it != m_clientBlockSizes.end(); ++it) {
        QTcpSocket* clientSocket = it.key();
        if (clientSocket && clientSocket->state() == QAbstractSocket::ConnectedState) {
            sendResponse(clientSocket, broadcastMessage);
            broadcastCount++;
        }
    }

    // 移除确认响应的发送
    qInfo() << "聊天消息已广播给" << broadcastCount << "个在线客户端，来自用户：" << username << "(" << account << ")";
}

// **辅助函数：处理私聊消息请求的逻辑**
void ChatServer::handlePrivateChatMessage(QTcpSocket* socket, const QString& senderAccount, const QString& content, const QString& targetAccount) {
    QJsonObject response;
    response["type"] = "chatMessage";

    // 验证输入数据
    if (senderAccount.isEmpty() || content.isEmpty() || targetAccount.isEmpty()) {
        response["status"] = "error";
        response["message"] = "私聊消息发送失败：发送者账号、接收者账号和消息内容不能为空。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "私聊消息发送失败：输入数据不完整";
        return;
    }

    // 验证发送者是否存在
    QSqlQuery senderQuery(m_db);
    senderQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    senderQuery.bindValue(":account", senderAccount);

    if (!senderQuery.exec() || !senderQuery.next()) {
        response["status"] = "error";
        response["message"] = "私聊消息发送失败：发送者不存在。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "私聊消息发送失败：发送者不存在：" << senderAccount;
        return;
    }

    QString senderUsername = senderQuery.value("username").toString();

    // 验证接收者是否存在
    QSqlQuery targetQuery(m_db);
    targetQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    targetQuery.bindValue(":account", targetAccount);

    if (!targetQuery.exec() || !targetQuery.next()) {
        response["status"] = "error";
        response["message"] = "私聊消息发送失败：接收者不存在。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "私聊消息发送失败：接收者不存在：" << targetAccount;
        return;
    }

    QString targetUsername = targetQuery.value("username").toString();

    // 构建私聊消息
    QJsonObject privateMessage;
    privateMessage["type"] = "chatMessage";
    privateMessage["status"] = "private";
    privateMessage["sender"] = senderAccount;
    privateMessage["username"] = senderUsername;
    privateMessage["target"] = targetAccount;
    privateMessage["targetUsername"] = targetUsername;
    privateMessage["content"] = content;
    privateMessage["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 找到目标用户的套接字并发送消息
    bool targetFound = false;
    for (auto it = m_clientBlockSizes.begin(); it != m_clientBlockSizes.end(); ++it) {
        QTcpSocket* clientSocket = it.key();
        if (clientSocket && clientSocket->state() == QAbstractSocket::ConnectedState) {
            // 这里需要一个方法来识别套接字对应的账号，暂时发送给所有在线用户
            // 实际应用中需要维护套接字到账号的映射
            sendResponse(clientSocket, privateMessage);
            targetFound = true;
        }
    }

    // 向发送者确认消息状态
    response["status"] = targetFound ? "success" : "error";
    response["message"] = targetFound ?
        "私聊消息已发送给 " + targetUsername + "。" :
        "私聊消息发送失败：目标用户不在线。";
    response["timestamp"] = privateMessage["timestamp"];
    sendResponse(socket, response);

    qInfo() << "私聊消息处理完成，从" << senderUsername << "(" << senderAccount << ")到" << targetUsername << "(" << targetAccount << ")";
}

// **辅助函数：处理用户信息更新请求的逻辑**
void ChatServer::handleUpdateUserInfo(QTcpSocket* socket, const QString& account, const QString& nickname, const QString& oldPassword, const QString& newPassword) {
    QJsonObject response;
    response["type"] = "updateUserInfo";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证输入数据
    if (account.isEmpty() || nickname.isEmpty() || oldPassword.isEmpty()) {
        response["status"] = "error";
        response["message"] = "用户信息更新失败：账号、昵称和原密码不能为空。";
        sendResponse(socket, response);
        qWarning() << "用户信息更新失败：输入数据不完整";
        return;
    }

    // 验证用户身份（检查账号和原密码）
    QSqlQuery authQuery(m_db);
    authQuery.prepare("SELECT username FROM Users WHERE account = :account AND password = :password COLLATE NOCASE");
    authQuery.bindValue(":account", account);
    authQuery.bindValue(":password", oldPassword);

    if (!authQuery.exec() || !authQuery.next()) {
        response["status"] = "error";
        response["message"] = "用户信息更新失败：原密码不正确。";
        sendResponse(socket, response);
        qWarning() << "用户信息更新失败：身份验证失败：" << account;
        return;
    }

    QString currentUsername = authQuery.value("username").toString();

    // 开始更新用户信息
    QSqlQuery updateQuery(m_db);
    QString updateSql;

    if (newPassword.isEmpty()) {
        // 只更新昵称
        updateSql = "UPDATE Users SET username = :nickname WHERE account = :account";
        updateQuery.prepare(updateSql);
        updateQuery.bindValue(":nickname", nickname);
        updateQuery.bindValue(":account", account);
    } else {
        // 同时更新昵称和密码
        updateSql = "UPDATE Users SET username = :nickname, password = :newPassword WHERE account = :account";
        updateQuery.prepare(updateSql);
        updateQuery.bindValue(":nickname", nickname);
        updateQuery.bindValue(":newPassword", newPassword);
        updateQuery.bindValue(":account", account);
    }

    if (updateQuery.exec()) {
        response["status"] = "success";
        if (newPassword.isEmpty()) {
            response["message"] = "昵称更新成功！新昵称：" + nickname;
            qInfo() << "用户昵称更新成功：账号=" << account << ", 原昵称=" << currentUsername << ", 新昵称=" << nickname;
        } else {
            response["message"] = "用户信息更新成功！新昵称：" + nickname + "，密码已更新。";
            qInfo() << "用户信息更新成功：账号=" << account << ", 原昵称=" << currentUsername << ", 新昵称=" << nickname << ", 密码已更新";
        }
        response["username"] = nickname;
        response["account"] = account;
    } else {
        response["status"] = "error";
        response["message"] = "用户信息更新失败：数据库错误 - " + updateQuery.lastError().text();
        qCritical() << "用户信息更新失败：数据库错误：" << updateQuery.lastError().text();
    }

    sendResponse(socket, response);
    qInfo() << "已发送用户信息更新响应给 [" << getPeerInfo(socket) << "]";
}
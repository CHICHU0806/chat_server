// chat_server.cpp

#include "chat_server.h" // 包含自己的头文件
#include <QHostAddress>    // 用于绑定IP地址
#include <QDebug>          // 用于在命令行输出调试和信息
#include <QJsonDocument>   // 用于解析JSON
#include <QJsonObject>     // 用于解析JSON
#include <QSqlError>       // 确保包含
#include <QDir>            // 用于处理文件路径和目录创建
#include <QCoreApplication> // 用于获取应用程序路径
#include <QJsonArray>

// 构造函数：初始化成员变量，连接信号和槽
ChatServer::ChatServer(QObject *parent)
    : QObject(parent),
      m_tcpServer(new QTcpServer(this))// 初始化 m_tcpServer
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
        // 创建消息表
        QString createMessageTableSql = "CREATE TABLE IF NOT EXISTS Messages ("
                                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                       "sender_account TEXT NOT NULL,"
                                       "receiver_account TEXT,"  // NULL表示公共消息
                                       "content TEXT NOT NULL,"
                                       "message_type TEXT NOT NULL,"  // 'public' 或 'private'
                                       "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                       "is_read BOOLEAN DEFAULT FALSE,"
                                       "FOREIGN KEY (sender_account) REFERENCES Users(account),"
                                       "FOREIGN KEY (receiver_account) REFERENCES Users(account)"
                                       ");";

        if (!query.exec(createMessageTableSql)) {
            qCritical() << "服务器无法创建 Messages 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 Messages 表已准备好。";
        }

        // 创建用户状态表
        QString createUserStatusTableSql = "CREATE TABLE IF NOT EXISTS UserStatus ("
                                          "account TEXT PRIMARY KEY,"
                                          "last_online DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                          "last_message_sync DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                          "is_online BOOLEAN DEFAULT FALSE,"
                                          "FOREIGN KEY (account) REFERENCES Users(account)"
                                          ");";

        if (!query.exec(createUserStatusTableSql)) {
            qCritical() << "服务器无法创建 UserStatus 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 UserStatus 表已准备好。";
        }

        // 创建消息已读状态表（用于公共消息的已读跟踪）
        QString createMessageReadStatusTableSql = "CREATE TABLE IF NOT EXISTS MessageReadStatus ("
                                                 "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                                 "message_id INTEGER NOT NULL,"
                                                 "user_account TEXT NOT NULL,"
                                                 "read_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                                 "FOREIGN KEY (message_id) REFERENCES Messages(id),"
                                                 "FOREIGN KEY (user_account) REFERENCES Users(account),"
                                                 "UNIQUE(message_id, user_account)"
                                                 ");";

        if (!query.exec(createMessageReadStatusTableSql)) {
            qCritical() << "服务器无法创建 MessageReadStatus 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 MessageReadStatus 表已准备好。";
        }

        // 创建好友关系表
        QString createFriendshipTableSql = "CREATE TABLE IF NOT EXISTS Friendships ("
                                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                          "user_account TEXT NOT NULL,"
                                          "friend_account TEXT NOT NULL,"
                                          "status TEXT NOT NULL,"  // 'pending', 'accepted', 'blocked'
                                          "created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                          "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                          "FOREIGN KEY (user_account) REFERENCES Users(account),"
                                          "FOREIGN KEY (friend_account) REFERENCES Users(account),"
                                          "UNIQUE(user_account, friend_account)"
                                          ");";

        if (!query.exec(createFriendshipTableSql)) {
            qCritical() << "服务器无法创建 Friendships 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 Friendships 表已准备好。";
        }

        // 创建索引以提高查询性能
        QStringList indexQueries = {
            "CREATE INDEX IF NOT EXISTS idx_messages_receiver_timestamp ON Messages(receiver_account, timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_messages_sender_timestamp ON Messages(sender_account, timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_messages_type_timestamp ON Messages(message_type, timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_user_status_last_sync ON UserStatus(last_message_sync);",
            "CREATE INDEX IF NOT EXISTS idx_message_read_status ON MessageReadStatus(message_id, user_account);",
            "CREATE INDEX IF NOT EXISTS idx_messages_is_read ON Messages(is_read);",
            "CREATE INDEX IF NOT EXISTS idx_users_account ON Users(account);",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON Users(username);",
            "CREATE INDEX IF NOT EXISTS idx_user_status_online ON UserStatus(is_online);",
            "CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON Messages(sender_account, receiver_account);"
        };

        for (const QString& indexSql : indexQueries) {
            if (!query.exec(indexSql)) {
                qWarning() << "创建索引失败：" << query.lastError().text() << "SQL:" << indexSql;
            }
        }

        qInfo() << "数据库索引创建完成。";
    }
    //数据库设置结束

    // 初始化 m_networkManager
    m_networkManager = new QNetworkAccessManager(this);

    // 将 m_tcpServer 发出的 newConnection() 信号连接到 ChatServer 的 onNewConnection() 槽函数
    connect(m_tcpServer, &QTcpServer::newConnection, this, &ChatServer::onNewConnection);

    // 将 m_networkManager 发出的 finished() 信号连接到 ChatServer 的 onAiApiReply() 槽函数
    connect(m_networkManager, &QNetworkAccessManager::finished, this, &ChatServer::onAiApiReply);

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
            //这里不立即 deleteLater()，依赖 onDisconnected() 槽来安全清理
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
        } else if (requestType == "chatMessage") {
            QString chatType = request["chatType"].toString(); // 改为 chatType
            QString targetAccount = request["targetAccount"].toString(); // 获取目标账号（私聊时使用）
            if (chatType == "private") {
                handlePrivateChatMessage(senderSocket, account, request["content"].toString(), targetAccount);
            } else if (chatType == "public"){
                handleChatMessage(senderSocket, account, request["content"].toString());
            }
            else if (chatType == "ai") {
                handleAiAsk(senderSocket, account, request["question"].toString());
            }
        }
        else if (requestType == "updateUserInfo") {
            QString nickname = request["nickname"].toString();
            QString oldPassword = request["oldPassword"].toString();
            QString newPassword = request["newPassword"].toString();
            handleUpdateUserInfo(senderSocket, account, nickname, oldPassword, newPassword);
        }
        else if (requestType == "searchFriend") {
            QString targetAccount = request["targetAccount"].toString();
            handleSearchFriend(senderSocket, account, targetAccount);
        }
        else if (requestType == "addFriend") {
            handleAddFriendRequest(senderSocket, request);
        }
        else if (requestType == "getFriendRequests") {
            handleGetFriendRequests(senderSocket, account);
        }
        else if (requestType == "acceptFriendRequest") {
            QString fromAccount = request["fromAccount"].toString();
            handleAcceptFriendRequest(senderSocket, account, fromAccount);
        }
        else if (requestType == "rejectFriendRequest") {
            QString fromAccount = request["fromAccount"].toString();
            handleRejectFriendRequest(senderSocket, account, fromAccount);
        }
        else if (requestType == "getFriendList") {
            handleGetFriendList(senderSocket, account);
        }
        else if (requestType == "getOfflineMessages") {
            handleGetOfflineMessages(senderSocket, account);
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

    // 清理账号映射
    if (m_socketToAccount.contains(senderSocket)) {
        QString account = m_socketToAccount.value(senderSocket);

        // 更新用户离线状态
        updateUserOnlineStatus(account, false);

        m_socketToAccount.remove(senderSocket);
        qInfo() << "用户 " << account << " 已下线";
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

void ChatServer::onAiApiReply(QNetworkReply* reply) {
    QTcpSocket* socket = (QTcpSocket*)reply->request().attribute(QNetworkRequest::User).value<void*>();
    if (!socket) return;

    QJsonObject response;
    response["type"] = "aiAnswer";
    response["status"] = "success";
    response["account"] = socket->property("aiAskAccount").toString();

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray respData = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(respData);
        QString aiAnswer;
        if (doc.isObject()) {
            // 解析 DeepSeek 返回的内容
            QJsonObject obj = doc.object();
            QJsonArray choices = obj["choices"].toArray();
            if (!choices.isEmpty()) {
                aiAnswer = choices[0].toObject()["message"].toObject()["content"].toString();
            }
        }
        qInfo() << "AI API回复已收到，状态：" << reply->error() << "，内容：" << reply->readAll();
        response["answer"] = aiAnswer;
    } else {
        response["status"] = "error";
        response["message"] = "AI服务请求失败：" + reply->errorString();
    }
    sendResponse(socket, response);
    reply->deleteLater();
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

        // 登录成功，初始化用户状态
        initializeUserStatus(account);

        response["status"] = "success";
        response["message"] = "登录成功";
        response["username"] = username;
        response["account"] = account;

        // 将套接字与账号关联
        m_socketToAccount.insert(socket, account);

        // 推送离线消息和离线好友申请
        pushOfflineMessages(socket, account);
        pushOfflineFriendRequests(socket, account);

        qInfo() << "登录成功：" << username << "(" << account << ") 来自 [" << getPeerInfo(socket) << "]";
    }else {
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

    // 保存公共消息到数据库
    saveMessageToDatabase(account, "", content, "public");

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

    // 向发送者发送确认响应
    QJsonObject confirmResponse;
    confirmResponse["type"] = "chatMessage";
    confirmResponse["status"] = "success";
    confirmResponse["message"] = "消息发送成功，已广播给 " + QString::number(broadcastCount) + " 个在线用户";
    confirmResponse["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    sendResponse(socket, confirmResponse);

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

    // 保存私聊消息到数据库
    saveMessageToDatabase(senderAccount, targetAccount, content, "private");

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

// **辅助函数：处理搜索好友请求的逻辑**
void ChatServer::handleSearchFriend(QTcpSocket* socket, const QString& account, const QString& targetAccount) {
    QJsonObject response;
    response["type"] = "searchFriend";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 检查是否搜索自己
    if (account == targetAccount) {
        response["status"] = "error";
        response["message"] = "不能添加自己为好友";
        sendResponse(socket, response);
        qWarning() << "搜索好友失败：用户尝试搜索自己：" << account;
        return;
    }

    // 验证当前用户是否存在
    QSqlQuery currentUserQuery(m_db);
    currentUserQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    currentUserQuery.bindValue(":account", account);

    if (!currentUserQuery.exec() || !currentUserQuery.next()) {
        response["status"] = "error";
        response["message"] = "搜索失败：当前用户不存在。";
        sendResponse(socket, response);
        qWarning() << "搜索好友失败：当前用户不存在：" << account;
        return;
    }

    // 搜索目标用户
    QSqlQuery targetUserQuery(m_db);
    targetUserQuery.prepare("SELECT username FROM Users WHERE account = :targetAccount COLLATE NOCASE");
    targetUserQuery.bindValue(":targetAccount", targetAccount);

    if (!targetUserQuery.exec() || !targetUserQuery.next()) {
        response["status"] = "error";
        response["message"] = "用户不存在";
        sendResponse(socket, response);
        qInfo() << "搜索好友：用户不存在 - 搜索者:" << account << ", 目标:" << targetAccount;
        return;
    }

    QString targetUsername = targetUserQuery.value("username").toString();

    // 检查目标用户是否在线
    bool isOnline = m_socketToAccount.values().contains(targetAccount);
    for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
        QTcpSocket* clientSocket = it.key();
        QString clientAccount = it.value();

        if (clientSocket &&
            clientSocket->state() == QAbstractSocket::ConnectedState &&
            clientAccount == targetAccount) {
            isOnline = true;
            break;
        }
    }

    // 构建成功响应
    response["status"] = "success";
    response["message"] = "用户找到";

    QJsonObject userInfo;
    userInfo["account"] = targetAccount;
    userInfo["username"] = targetUsername;
    userInfo["isOnline"] = isOnline;
    //TODO:头像相关内容
    response["userInfo"] = userInfo;

    sendResponse(socket, response);
    qInfo() << "搜索好友成功：搜索者=" << account << ", 找到用户=" << targetUsername << "(" << targetAccount << ")";
}

// **辅助函数：处理添加好友请求的逻辑**
void ChatServer::handleAddFriendRequest(QTcpSocket* socket, const QJsonObject& request) {
    QString senderAccount = request["account"].toString();
    QString targetAccount = request["targetAccount"].toString();

    QJsonObject response;
    response["type"] = "addFriend";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证输入数据
    if (senderAccount.isEmpty() || targetAccount.isEmpty()) {
        response["status"] = "error";
        response["message"] = "添加好友失败：发送者账号和目标账号不能为空。";
        sendResponse(socket, response);
        qWarning() << "添加好友失败：输入数据不完整";
        return;
    }

    // 检查是否添加自己
    if (senderAccount == targetAccount) {
        response["status"] = "error";
        response["message"] = "添加好友失败：不能添加自己为好友。";
        sendResponse(socket, response);
        qWarning() << "添加好友失败：用户尝试添加自己：" << senderAccount;
        return;
    }

    // 验证发送者是否存在且已登录
    if (!m_socketToAccount.contains(socket) || m_socketToAccount[socket] != senderAccount) {
        response["status"] = "error";
        response["message"] = "添加好友失败：用户未登录或身份验证失败。";
        sendResponse(socket, response);
        qWarning() << "添加好友失败：身份验证失败：" << senderAccount;
        return;
    }

    // 获取发送者用户名
    QSqlQuery senderQuery(m_db);
    senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
    senderQuery.bindValue(":account", senderAccount);

    if (!senderQuery.exec() || !senderQuery.next()) {
        response["status"] = "error";
        response["message"] = "添加好友失败：发送者信息获取失败。";
        sendResponse(socket, response);
        qWarning() << "添加好友失败：发送者信息获取失败：" << senderAccount;
        return;
    }

    QString senderUsername = senderQuery.value("username").toString();

    // 验证目标用户是否存在
    QSqlQuery targetQuery(m_db);
    targetQuery.prepare("SELECT username FROM Users WHERE account = :account");
    targetQuery.bindValue(":account", targetAccount);

    if (!targetQuery.exec() || !targetQuery.next()) {
        response["status"] = "error";
        response["message"] = "添加好友失败：目标用户不存在。";
        sendResponse(socket, response);
        qWarning() << "添加好友失败：目标用户不存在：" << targetAccount;
        return;
    }

    QString targetUsername = targetQuery.value("username").toString();

    // 检查是否已经是好友关系
    QSqlQuery friendshipQuery(m_db);
    friendshipQuery.prepare("SELECT status FROM Friendships WHERE "
                           "(user_account = :sender AND friend_account = :target) OR "
                           "(user_account = :target AND friend_account = :sender)");
    friendshipQuery.bindValue(":sender", senderAccount);
    friendshipQuery.bindValue(":target", targetAccount);

    if (friendshipQuery.exec() && friendshipQuery.next()) {
        QString status = friendshipQuery.value("status").toString();
        if (status == "accepted") {
            response["status"] = "error";
            response["message"] = "添加好友失败：你们已经是好友了。";
        } else if (status == "pending") {
            response["status"] = "error";
            response["message"] = "添加好友失败：已存在好友申请关系。";
        } else if (status == "blocked") {
            response["status"] = "error";
            response["message"] = "添加好友失败：无法发送好友申请。";
        }
        sendResponse(socket, response);
        qWarning() << "添加好友失败：已存在好友关系，状态：" << status << "发送者：" << senderAccount << "目标：" << targetAccount;
        return;
    }

    // 插入好友申请记录
    QSqlQuery insertQuery(m_db);
    insertQuery.prepare("INSERT INTO Friendships (user_account, friend_account, status, created_at, updated_at) "
                       "VALUES (:sender, :target, 'pending', :timestamp, :timestamp)");
    insertQuery.bindValue(":sender", senderAccount);
    insertQuery.bindValue(":target", targetAccount);
    insertQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));

    if (!insertQuery.exec()) {
        response["status"] = "error";
        response["message"] = "添加好友失败：数据库错误 - " + insertQuery.lastError().text();
        sendResponse(socket, response);
        qCritical() << "添加好友失败：数据库错误：" << insertQuery.lastError().text();
        return;
    }

    // 发送成功响应给申请发送者
    response["status"] = "success";
    response["message"] = "好友申请已发送给 " + targetUsername + "。";
    response["targetAccount"] = targetAccount;
    response["targetUsername"] = targetUsername;
    sendResponse(socket, response);

    // 如果目标用户在线，推送好友申请通知
    pushFriendRequestToOnlineUser(senderAccount, senderUsername, targetAccount);

    qInfo() << "好友申请处理完成：" << senderUsername << "(" << senderAccount << ") 向 "
            << targetUsername << "(" << targetAccount << ") 发送好友申请";
}

// 保存消息到数据库
void ChatServer::saveMessageToDatabase(const QString& senderAccount, const QString& receiverAccount,
                                     const QString& content, const QString& messageType) {
    QSqlQuery insertQuery(m_db);
    insertQuery.prepare("INSERT INTO Messages (sender_account, receiver_account, content, message_type, timestamp) "
                       "VALUES (:sender, :receiver, :content, :type, :timestamp)");

    insertQuery.bindValue(":sender", senderAccount);
    insertQuery.bindValue(":receiver", receiverAccount.isEmpty() ? QVariant() : receiverAccount);
    insertQuery.bindValue(":content", content);
    insertQuery.bindValue(":type", messageType);
    insertQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));

    if (!insertQuery.exec()) {
        qCritical() << "保存消息到数据库失败：" << insertQuery.lastError().text();
    } else {
        qDebug() << "消息已保存到数据库：" << messageType << "类型，发送者：" << senderAccount;
    }
}

// 更新用户在线状态
void ChatServer::updateUserOnlineStatus(const QString& account, bool isOnline) {
    QSqlQuery updateQuery(m_db);

    if (isOnline) {
        // 用户上线
        updateQuery.prepare("INSERT OR REPLACE INTO UserStatus (account, last_online, is_online) "
                           "VALUES (:account, :timestamp, :online)");
    } else {
        // 用户下线
        updateQuery.prepare("UPDATE UserStatus SET last_online = :timestamp, is_online = :online "
                           "WHERE account = :account");
    }

    updateQuery.bindValue(":account", account);
    updateQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));
    updateQuery.bindValue(":online", isOnline);

    if (!updateQuery.exec()) {
        qWarning() << "更新用户状态失败：" << updateQuery.lastError().text();
    }
}

// 更新用户最后同步时间
void ChatServer::updateUserLastSync(const QString& account) {
    QSqlQuery updateQuery(m_db);
    updateQuery.prepare("UPDATE UserStatus SET last_message_sync = :timestamp WHERE account = :account");
    updateQuery.bindValue(":account", account);
    updateQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));

    if (!updateQuery.exec()) {
        qWarning() << "更新用户同步时间失败：" << updateQuery.lastError().text();
    }
}

// 处理获取离线消息请求
void ChatServer::handleGetOfflineMessages(QTcpSocket* socket, const QString& account) {
    qInfo() << "处理获取离线消息请求，账号：" << account;

    // 验证账号是否已登录
    if (!m_socketToAccount.contains(socket) || m_socketToAccount[socket] != account) {
        sendErrorResponse(socket, "未登录或账号不匹配", "getOfflineMessages");
        return;
    }

    // 调用现有的推送离线消息函数
    pushOfflineMessages(socket, account);
}

// 推送离线消息
void ChatServer::pushOfflineMessages(QTcpSocket* socket, const QString& account) {
    // 获取用户最后同步时间
    QSqlQuery syncQuery(m_db);
    syncQuery.prepare("SELECT last_message_sync FROM UserStatus WHERE account = :account");
    syncQuery.bindValue(":account", account);

    QString lastSyncTime;
    if (syncQuery.exec() && syncQuery.next()) {
        lastSyncTime = syncQuery.value("last_message_sync").toString();
    } else {
        // 如果没有同步记录，使用很早的时间来获取所有消息
        lastSyncTime = "2000-01-01T00:00:00";
    }

    QJsonArray allOfflineMessages;

    // 查询离线期间的公共消息
    QSqlQuery publicMsgQuery(m_db);
    publicMsgQuery.prepare("SELECT sender_account, content, timestamp "
                          "FROM Messages "
                          "WHERE message_type = 'public' AND timestamp > :lastSync "
                          "ORDER BY timestamp ASC");
    publicMsgQuery.bindValue(":lastSync", lastSyncTime);

    if (publicMsgQuery.exec()) {
        while (publicMsgQuery.next()) {
            QString senderAccount = publicMsgQuery.value("sender_account").toString();
            QString content = publicMsgQuery.value("content").toString();
            QString timestamp = publicMsgQuery.value("timestamp").toString();

            // 获取发送者用户名
            QSqlQuery senderQuery(m_db);
            senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
            senderQuery.bindValue(":account", senderAccount);

            QString senderUsername = senderAccount; // 默认值
            if (senderQuery.exec() && senderQuery.next()) {
                senderUsername = senderQuery.value("username").toString();
            }

            // 构建离线消息 JSON 对象
            QJsonObject offlineMessage;
            offlineMessage["type"] = "offline_messages";
            offlineMessage["status"] = "offline_broadcast";
            offlineMessage["sender"] = senderAccount;
            offlineMessage["username"] = senderUsername;
            offlineMessage["content"] = content;
            offlineMessage["timestamp"] = timestamp;

            // *** 关键改进：将消息添加到数组中，而不是立即发送 ***
            allOfflineMessages.append(offlineMessage);
        }
    }

    // 查询离线期间的私聊消息（接收的）
    QSqlQuery privateMsgQuery(m_db);
    privateMsgQuery.prepare("SELECT sender_account, content, timestamp "
                           "FROM Messages "
                           "WHERE message_type = 'private' AND receiver_account = :account "
                           "AND timestamp > :lastSync AND is_read = FALSE "
                           "ORDER BY timestamp ASC");
    privateMsgQuery.bindValue(":account", account);
    privateMsgQuery.bindValue(":lastSync", lastSyncTime);

    if (privateMsgQuery.exec()) {
        while (privateMsgQuery.next()) {
            QString senderAccount = privateMsgQuery.value("sender_account").toString();
            QString content = privateMsgQuery.value("content").toString();
            QString timestamp = privateMsgQuery.value("timestamp").toString();

            // 获取发送者用户名
            QSqlQuery senderQuery(m_db);
            senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
            senderQuery.bindValue(":account", senderAccount);

            QString senderUsername = senderAccount;
            if (senderQuery.exec() && senderQuery.next()) {
                senderUsername = senderQuery.value("username").toString();
            }

            // 构建离线私聊消息 JSON 对象
            QJsonObject offlineMessage;
            offlineMessage["type"] = "offline_messages";
            offlineMessage["status"] = "offline_private";
            offlineMessage["sender"] = senderAccount;
            offlineMessage["username"] = senderUsername;
            offlineMessage["target"] = account;
            offlineMessage["content"] = content;
            offlineMessage["timestamp"] = timestamp;

            // *** 关键改进：将消息添加到数组中，而不是立即发送 ***
            allOfflineMessages.append(offlineMessage);
        }
    }

    if (!allOfflineMessages.isEmpty()) {
        QJsonObject offlineResponse;
        offlineResponse["type"] = "offline_messages"; // 这是客户端期望的类型
        offlineResponse["messageCount"] = allOfflineMessages.size();
        offlineResponse["messages"] = allOfflineMessages; // 包含所有消息的数组
        sendResponse(socket, offlineResponse); // 只调用一次发送
        qInfo() << "已推送" << allOfflineMessages.size() << "条离线消息给用户" << account;
    }

    // 更新用户最后同步时间
    updateUserLastSync(account);
}

//推送在线好友申请
void ChatServer::pushFriendRequestToOnlineUser(const QString& fromAccount, const QString& fromUsername, const QString& toAccount) {
    // 查找目标用户的socket连接
    for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
        if (it.value() == toAccount) {
            QTcpSocket* targetSocket = it.key();

            QJsonObject notification;
            notification["type"] = "friendRequest";
            notification["status"] = "onlineRequest";  // 添加状态标识
            notification["fromAccount"] = fromAccount;
            notification["fromUsername"] = fromUsername;
            notification["toAccount"] = toAccount;
            notification["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);  // 添加时间戳

            sendResponse(targetSocket, notification);
            qInfo() << "已推送好友申请通知：" << fromAccount << "(" << fromUsername << ") -> " << toAccount;
            break;
        }
    }
}

// 推送离线好友申请
void ChatServer::pushOfflineFriendRequests(QTcpSocket* socket, const QString& account) {
    // 查询发送给该用户的待处理好友申请
    QSqlQuery friendRequestQuery(m_db);
    friendRequestQuery.prepare("SELECT user_account, created_at FROM Friendships "
                              "WHERE friend_account = :account AND status = 'pending' "
                              "ORDER BY created_at ASC");
    friendRequestQuery.bindValue(":account", account);

    int requestCount = 0;
    if (friendRequestQuery.exec()) {
        while (friendRequestQuery.next()) {
            QString fromAccount = friendRequestQuery.value("user_account").toString();
            QString timestamp = friendRequestQuery.value("created_at").toString();

            // 获取发送者用户名
            QSqlQuery senderQuery(m_db);
            senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
            senderQuery.bindValue(":account", fromAccount);

            QString fromUsername = fromAccount; // 默认值
            if (senderQuery.exec() && senderQuery.next()) {
                fromUsername = senderQuery.value("username").toString();
            }

            // 构建好友申请通知
            QJsonObject friendRequestNotification;
            friendRequestNotification["type"] = "friendRequest";
            friendRequestNotification["status"] = "offlineRequest";
            friendRequestNotification["fromAccount"] = fromAccount;
            friendRequestNotification["fromUsername"] = fromUsername;
            friendRequestNotification["toAccount"] = account;
            friendRequestNotification["timestamp"] = timestamp;

            sendResponse(socket, friendRequestNotification);
            requestCount++;
        }
    }

    if (requestCount > 0) {
        qInfo() << "已推送离线好友申请给用户" << account << "：" << requestCount << "条申请";
    }
}

// 初始化用户状态
void ChatServer::initializeUserStatus(const QString& account) {
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT account FROM UserStatus WHERE account = :account");
    checkQuery.bindValue(":account", account);

    if (checkQuery.exec() && !checkQuery.next()) {
        // 用户状态记录不存在，创建新记录
        QSqlQuery insertQuery(m_db);
        insertQuery.prepare("INSERT INTO UserStatus (account, last_online, last_message_sync, is_online) "
                           "VALUES (:account, :timestamp, :timestamp, :online)");
        insertQuery.bindValue(":account", account);
        insertQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));
        insertQuery.bindValue(":online", true);

        if (!insertQuery.exec()) {
            qWarning() << "初始化用户状态失败：" << insertQuery.lastError().text();
        }
    } else {
        // 更新现有记录
        updateUserOnlineStatus(account, true);
    }
}

// **辅助函数：处理获取好友申请请求的逻辑**
void ChatServer::handleGetFriendRequests(QTcpSocket* socket, const QString& account) {
    QJsonObject response;
    response["type"] = "getFriendRequests";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证账号是否已登录
    if (!m_socketToAccount.contains(socket) || m_socketToAccount[socket] != account) {
        response["status"] = "error";
        response["message"] = "获取好友申请失败：用户未登录或身份验证失败。";
        sendResponse(socket, response);
        qWarning() << "获取好友申请失败：身份验证失败：" << account;
        return;
    }

    // 查询发送给该用户的待处理好友申请
    QSqlQuery friendRequestQuery(m_db);
    friendRequestQuery.prepare("SELECT user_account, created_at FROM Friendships "
                              "WHERE friend_account = :account AND status = 'pending' "
                              "ORDER BY created_at DESC");
    friendRequestQuery.bindValue(":account", account);

    QJsonArray requestsArray;
    int requestCount = 0;

    if (friendRequestQuery.exec()) {
        while (friendRequestQuery.next()) {
            QString fromAccount = friendRequestQuery.value("user_account").toString();
            QString timestamp = friendRequestQuery.value("created_at").toString();

            // 获取发送者用户名
            QSqlQuery senderQuery(m_db);
            senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
            senderQuery.bindValue(":account", fromAccount);

            QString fromUsername = fromAccount; // 默认值
            if (senderQuery.exec() && senderQuery.next()) {
                fromUsername = senderQuery.value("username").toString();
            }

            // 检查发送者是否在线
            bool isOnline = false;
            for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
                if (it.value() == fromAccount && it.key()->state() == QAbstractSocket::ConnectedState) {
                    isOnline = true;
                    break;
                }
            }

            // 构建好友申请信息
            QJsonObject requestInfo;
            requestInfo["fromAccount"] = fromAccount;
            requestInfo["fromUsername"] = fromUsername;
            requestInfo["timestamp"] = timestamp;
            requestInfo["isOnline"] = isOnline;

            requestsArray.append(requestInfo);
            requestCount++;
        }
    } else {
        response["status"] = "error";
        response["message"] = "获取好友申请失败：数据库查询错误 - " + friendRequestQuery.lastError().text();
        sendResponse(socket, response);
        qCritical() << "获取好友申请失败：数据库错误：" << friendRequestQuery.lastError().text();
        return;
    }

    // 构建成功响应
    response["status"] = "success";
    response["message"] = "成功获取好友申请列表";
    response["requests"] = requestsArray;
    response["requestCount"] = requestCount;

    sendResponse(socket, response);
    qInfo() << "已发送好友申请列表给用户" << account << "：共" << requestCount << "条申请";
}

// **辅助函数：处理接受好友申请请求的逻辑**
void ChatServer::handleAcceptFriendRequest(QTcpSocket* socket, const QString& account, const QString& fromAccount) {
    QJsonObject response;
    response["type"] = "acceptFriendRequest";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证输入数据
    if (account.isEmpty() || fromAccount.isEmpty()) {
        response["status"] = "error";
        response["message"] = "接受好友申请失败：账号和请求者账号不能为空。";
        sendResponse(socket, response);
        qWarning() << "接受好友申请失败：输入数据不完整";
        return;
    }

    // 检查好友申请是否存在
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT status FROM Friendships WHERE "
                      "user_account = :fromAccount AND friend_account = :account");
    checkQuery.bindValue(":fromAccount", fromAccount);
    checkQuery.bindValue(":account", account);

    if (!checkQuery.exec() || !checkQuery.next()) {
        response["status"] = "error";
        response["message"] = "接受好友申请失败：未找到相关请求。";
        sendResponse(socket, response);
        qWarning() << "接受好友申请失败：未找到请求记录，发送者：" << fromAccount << " 接收者：" << account;
        return;
    }

    QString status = checkQuery.value("status").toString();
    if (status != "pending") {
        response["status"] = "error";
        response["message"] = "接受好友申请失败：请求状态不正确。";
        sendResponse(socket, response);
        qWarning() << "接受好友申请失败：请求状态不正确，状态：" << status;
        return;
    }

    // 更新好友关系为已接受
    QSqlQuery updateQuery(m_db);
    updateQuery.prepare("UPDATE Friendships SET status = 'accepted', updated_at = :timestamp "
                       "WHERE user_account = :fromAccount AND friend_account = :account");
    updateQuery.bindValue(":fromAccount", fromAccount);
    updateQuery.bindValue(":account", account);
    updateQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));

    if (!updateQuery.exec()) {
        response["status"] = "error";
        response["message"] = "接受好友申请失败：数据库错误 - " + updateQuery.lastError().text();
        sendResponse(socket, response);
        qCritical() << "接受好友申请失败：数据库错误：" << updateQuery.lastError().text();
        return;
    }

    response["status"] = "success";
    response["message"] = "已成功接受来自 " + fromAccount + " 的好友申请。";

    // 如果申请发送者在线，推送好友关系更新通知
    QTcpSocket* senderSocket = nullptr;
    for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
        if (it.value() == fromAccount) {
            senderSocket = it.key();
            break;
        }
    }

    if (senderSocket && senderSocket->state() == QAbstractSocket::ConnectedState) {
        QJsonObject notification;
        notification["type"] = "friendRequestResponse";
        notification["status"] = "accepted";
        notification["fromAccount"] = fromAccount;
        notification["toAccount"] = account;
        notification["message"] = "你的好友申请已被 " + account + " 接受";
        notification["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

        sendResponse(senderSocket, notification);
        qInfo() << "已推送好友申请被接受通知给申请发送者：" << fromAccount;
    }

    sendResponse(socket, response);
    qInfo() << "已处理接受好友申请请求：" << fromAccount << " -> " << account;
}

// **辅助函数：处理拒绝好友申请请求的逻辑**
void ChatServer::handleRejectFriendRequest(QTcpSocket* socket, const QString& account, const QString& fromAccount) {
    QJsonObject response;
    response["type"] = "rejectFriendRequest";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证输入数据
    if (account.isEmpty() || fromAccount.isEmpty()) {
        response["status"] = "error";
        response["message"] = "拒绝好友申请失败：账号和请求者账号不能为空。";
        sendResponse(socket, response);
        qWarning() << "拒绝好友申请失败：输入数据不完整";
        return;
    }

    // 检查好友申请是否存在
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT status FROM Friendships WHERE "
                      "user_account = :fromAccount AND friend_account = :account");
    checkQuery.bindValue(":fromAccount", fromAccount);
    checkQuery.bindValue(":account", account);

    if (!checkQuery.exec() || !checkQuery.next()) {
        response["status"] = "error";
        response["message"] = "拒绝好友申请失败：未找到相关请求。";
        sendResponse(socket, response);
        qWarning() << "拒绝好友申请失败：未找到请求记录，发送者：" << fromAccount << " 接收者：" << account;
        return;
    }

    QString status = checkQuery.value("status").toString();
    if (status != "pending") {
        response["status"] = "error";
        response["message"] = "拒绝好友申请失败：请求状态不正确。";
        sendResponse(socket, response);
        qWarning() << "拒绝好友申请失败：请求状态不正确，状态：" << status;
        return;
    }

    // 删除好友申请记录
    QSqlQuery deleteQuery(m_db);
    deleteQuery.prepare("DELETE FROM Friendships WHERE "
                       "user_account = :fromAccount AND friend_account = :account");
    deleteQuery.bindValue(":fromAccount", fromAccount);
    deleteQuery.bindValue(":account", account);

    if (!deleteQuery.exec()) {
        response["status"] = "error";
        response["message"] = "拒绝好友申请失败：数据库错误 - " + deleteQuery.lastError().text();
        sendResponse(socket, response);
        qCritical() << "拒绝好友申请失败：数据库错误：" << deleteQuery.lastError().text();
        return;
    }

    response["status"] = "success";
    response["message"] = "已成功拒绝来自 " + fromAccount + " 的好友申请。";

    // 如果申请发送者在线，推送好友申请被拒绝通知
    QTcpSocket* senderSocket = nullptr;
    for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
        if (it.value() == fromAccount) {
            senderSocket = it.key();
            break;
        }
    }

    if (senderSocket && senderSocket->state() == QAbstractSocket::ConnectedState) {
        QJsonObject notification;
        notification["type"] = "friendRequestResponse";
        notification["status"] = "rejected";
        notification["fromAccount"] = fromAccount;
        notification["toAccount"] = account;
        notification["message"] = "你的好友申请已被 " + account + " 拒绝";
        notification["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

        sendResponse(senderSocket, notification);
        qInfo() << "已推送好友申请被拒绝通知给申请发送者：" << fromAccount;
    }

    sendResponse(socket, response);
    qInfo() << "已处理拒绝好友申请请求：" << fromAccount << " -> " << account;
}

// **辅助函数：处理获取好友列表请求的逻辑**
void ChatServer::handleGetFriendList(QTcpSocket* socket, const QString& account) {
    QJsonObject response;
    response["type"] = "getFriendList";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证账号是否已登录
    if (!m_socketToAccount.contains(socket) || m_socketToAccount[socket] != account) {
        response["status"] = "error";
        response["message"] = "获取好友列表失败：用户未登录或身份验证失败。";
        sendResponse(socket, response);
        qWarning() << "获取好友列表失败：身份验证失败：" << account;
        return;
    }

    // 查询该用户的好友关系（双向查询）
    QSqlQuery friendListQuery(m_db);
    friendListQuery.prepare("SELECT DISTINCT "
                           "CASE "
                           "  WHEN user_account = :account THEN friend_account "
                           "  ELSE user_account "
                           "END AS friend_account "
                           "FROM Friendships "
                           "WHERE (user_account = :account OR friend_account = :account) "
                           "AND status = 'accepted' "
                           "ORDER BY friend_account");
    friendListQuery.bindValue(":account", account);

    QJsonArray friendsArray;
    int friendCount = 0;

    if (friendListQuery.exec()) {
        while (friendListQuery.next()) {
            QString friendAccount = friendListQuery.value("friend_account").toString();

            // 获取好友用户名
            QSqlQuery friendInfoQuery(m_db);
            friendInfoQuery.prepare("SELECT username FROM Users WHERE account = :account");
            friendInfoQuery.bindValue(":account", friendAccount);

            QString friendUsername = friendAccount; // 默认值
            if (friendInfoQuery.exec() && friendInfoQuery.next()) {
                friendUsername = friendInfoQuery.value("username").toString();
            }

            // 检查好友是否在线
            bool isOnline = false;
            for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
                if (it.value() == friendAccount && it.key()->state() == QAbstractSocket::ConnectedState) {
                    isOnline = true;
                    break;
                }
            }

            // 构建好友信息
            QJsonObject friendInfo;
            friendInfo["account"] = friendAccount;
            friendInfo["username"] = friendUsername;
            friendInfo["isOnline"] = isOnline;
            // TODO: 可以在这里添加头像、个性签名等信息

            friendsArray.append(friendInfo);
            friendCount++;
        }
    } else {
        response["status"] = "error";
        response["message"] = "获取好友列表失败：数据库查询错误 - " + friendListQuery.lastError().text();
        sendResponse(socket, response);
        qCritical() << "获取好友列表失败：数据库错误：" << friendListQuery.lastError().text();
        return;
    }

    // 构建成功响应
    response["status"] = "success";
    response["message"] = "成功获取好友列表";
    response["friends"] = friendsArray;
    response["friendCount"] = friendCount;

    sendResponse(socket, response);
    qInfo() << "已发送好友列表给用户" << account << "：共" << friendCount << "个好友";
}

void ChatServer::handleAiAsk(QTcpSocket* socket, const QString& account, const QString& question) {
    qInfo() << "AI问答请求已收到：" << account << question;
    // 构造 DeepSeek API 请求
    QUrl url("https://api.deepseek.com/chat/completions"); // 替换为实际API地址
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", "Bearer sk-08852504a8714c60a1351fb4f974bc51");

    QJsonObject payload;
    payload["model"] = "deepseek-chat"; // 根据API文档填写
    QJsonArray messages;
    QJsonObject userMsg;
    userMsg["role"] = "user";
    userMsg["content"] = question;
    messages.append(userMsg);
    payload["messages"] = messages;

    QByteArray data = QJsonDocument(payload).toJson();

    //获取 QNetworkReply 对象**
    QNetworkReply* reply = m_networkManager->post(request, data);

    //将 socket 指针作为属性存储到 reply 中**
    reply->setProperty("aiAskSocket", QVariant::fromValue((void*)socket));

    connect(reply, &QNetworkReply::finished, this, &ChatServer::onAiAskReply);
}
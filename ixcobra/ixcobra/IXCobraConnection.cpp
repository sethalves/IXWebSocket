/*
 *  IXCobraConnection.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2017-2018 Machine Zone. All rights reserved.
 */

#include "IXCobraConnection.h"
#include <ixcrypto/IXHMac.h>
#include <ixwebsocket/IXWebSocket.h>

#include <algorithm>
#include <stdexcept>
#include <cmath>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>


namespace ix
{
    TrafficTrackerCallback CobraConnection::_trafficTrackerCallback = nullptr;
    PublishTrackerCallback CobraConnection::_publishTrackerCallback = nullptr;
    constexpr size_t CobraConnection::kQueueMaxSize;
    constexpr CobraConnection::MsgId CobraConnection::kInvalidMsgId;

    CobraConnection::CobraConnection() :
        _webSocket(new WebSocket()),
        _publishMode(CobraConnection_PublishMode_Immediate),
        _authenticated(false),
        _eventCallback(nullptr),
        _id(1)
    {
        _pdu.SetObject();
        _pdu.AddMember("action",
                       "rtm/publish",
                       _pdu.GetAllocator());

        _webSocket->addSubProtocol("json");
        initWebSocketOnMessageCallback();
    }

    CobraConnection::~CobraConnection()
    {
        disconnect();
        setEventCallback(nullptr);
    }

    void CobraConnection::setTrafficTrackerCallback(const TrafficTrackerCallback& callback)
    {
        _trafficTrackerCallback = callback;
    }

    void CobraConnection::resetTrafficTrackerCallback()
    {
        setTrafficTrackerCallback(nullptr);
    }

    void CobraConnection::invokeTrafficTrackerCallback(size_t size, bool incoming)
    {
        if (_trafficTrackerCallback)
        {
            _trafficTrackerCallback(size, incoming);
        }
    }

    void CobraConnection::setPublishTrackerCallback(const PublishTrackerCallback& callback)
    {
        _publishTrackerCallback = callback;
    }

    void CobraConnection::resetPublishTrackerCallback()
    {
        setPublishTrackerCallback(nullptr);
    }

    void CobraConnection::invokePublishTrackerCallback(bool sent, bool acked)
    {
        if (_publishTrackerCallback)
        {
            _publishTrackerCallback(sent, acked);
        }
    }

    void CobraConnection::setEventCallback(const EventCallback& eventCallback)
    {
        std::lock_guard<std::mutex> lock(_eventCallbackMutex);
        _eventCallback = eventCallback;
    }

    void CobraConnection::invokeEventCallback(ix::CobraConnectionEventType eventType,
                                              const std::string& errorMsg,
                                              const WebSocketHttpHeaders& headers,
                                              const std::string& subscriptionId,
                                              CobraConnection::MsgId msgId)
    {
        std::lock_guard<std::mutex> lock(_eventCallbackMutex);
        if (_eventCallback)
        {
            _eventCallback(eventType, errorMsg, headers, subscriptionId, msgId);
        }
    }

    void CobraConnection::invokeErrorCallback(const std::string& errorMsg,
                                              const std::string& serializedPdu)
    {
        std::stringstream ss;
        ss << errorMsg << " : received pdu => " << serializedPdu;
        invokeEventCallback(ix::CobraConnection_EventType_Error, ss.str());
    }

    void CobraConnection::disconnect()
    {
        _authenticated = false;
        _webSocket->stop();
    }

    void CobraConnection::initWebSocketOnMessageCallback()
    {
        _webSocket->setOnMessageCallback(
            [this](const ix::WebSocketMessagePtr& msg)
            {
                CobraConnection::invokeTrafficTrackerCallback(msg->wireSize, true);

                std::stringstream ss;
                if (msg->type == ix::WebSocketMessageType::Open)
                {
                    invokeEventCallback(ix::CobraConnection_EventType_Open,
                                        std::string(),
                                        msg->openInfo.headers);
                    sendHandshakeMessage();
                }
                else if (msg->type == ix::WebSocketMessageType::Close)
                {
                    _authenticated = false;

                    std::stringstream ss;
                    ss << "Close code " << msg->closeInfo.code;
                    ss << " reason " << msg->closeInfo.reason;
                    invokeEventCallback(ix::CobraConnection_EventType_Closed,
                                        ss.str());
                }
                else if (msg->type == ix::WebSocketMessageType::Message)
                {
                    rapidjson::Document document;
                    if (document.Parse(msg->str.c_str()).HasParseError())
                    {
                        invokeErrorCallback("Invalid json", msg->str);
                        return;
                    }

                    if (!document.HasMember("action"))
                    {
                        invokeErrorCallback("Missing action", msg->str);
                        return;
                    }

                    std::string action = document["action"].GetString();

                    if (action == "auth/handshake/ok")
                    {
                        if (!handleHandshakeResponse(document))
                        {
                            invokeErrorCallback("Error extracting nonce from handshake response", msg->str);
                        }
                    }
                    else if (action == "auth/handshake/error")
                    {
                        invokeErrorCallback("Handshake error", msg->str);
                    }
                    else if (action == "auth/authenticate/ok")
                    {
                        _authenticated = true;
                        invokeEventCallback(ix::CobraConnection_EventType_Authenticated);
                        flushQueue();
                    }
                    else if (action == "auth/authenticate/error")
                    {
                        invokeErrorCallback("Authentication error", msg->str);
                    }
                    else if (action == "rtm/subscription/data")
                    {
                        handleSubscriptionData(document);
                    }
                    else if (action == "rtm/subscribe/ok")
                    {
                        if (!handleSubscriptionResponse(document))
                        {
                            invokeErrorCallback("Error processing subscribe response", msg->str);
                        }
                    }
                    else if (action == "rtm/subscribe/error")
                    {
                        invokeErrorCallback("Subscription error", msg->str);
                    }
                    else if (action == "rtm/unsubscribe/ok")
                    {
                        if (!handleUnsubscriptionResponse(document))
                        {
                            invokeErrorCallback("Error processing unsubscribe response", msg->str);
                        }
                    }
                    else if (action == "rtm/unsubscribe/error")
                    {
                        invokeErrorCallback("Unsubscription error", msg->str);
                    }
                    else if (action == "rtm/publish/ok")
                    {
                        if (!handlePublishResponse(document))
                        {
                            invokeErrorCallback("Error processing publish response", msg->str);
                        }
                    }
                    else if (action == "rtm/publish/error")
                    {
                        invokeErrorCallback("Publish error", msg->str);
                    }
                    else
                    {
                        invokeErrorCallback("Un-handled message type", msg->str);
                    }
                }
                else if (msg->type == ix::WebSocketMessageType::Error)
                {
                    std::stringstream ss;
                    ss << "Connection error: " << msg->errorInfo.reason      << std::endl;
                    ss << "#retries: "         << msg->errorInfo.retries     << std::endl;
                    ss << "Wait time(ms): "    << msg->errorInfo.wait_time   << std::endl;
                    ss << "HTTP Status: "      << msg->errorInfo.http_status << std::endl;
                    invokeErrorCallback(ss.str(), std::string());
                }
        });
    }

    void CobraConnection::setPublishMode(CobraConnectionPublishMode publishMode)
    {
        _publishMode = publishMode;
    }

    CobraConnectionPublishMode CobraConnection::getPublishMode()
    {
        return _publishMode;
    }

    void CobraConnection::configure(const std::string& appkey,
                                    const std::string& endpoint,
                                    const std::string& rolename,
                                    const std::string& rolesecret,
                                    const WebSocketPerMessageDeflateOptions& webSocketPerMessageDeflateOptions)
    {
        _roleName = rolename;
        _roleSecret = rolesecret;

        std::stringstream ss;
        ss << endpoint;
        ss << "/v2?appkey=";
        ss << appkey;

        std::string url = ss.str();
        _webSocket->setUrl(url);
        _webSocket->setPerMessageDeflateOptions(webSocketPerMessageDeflateOptions);
    }

    //
    // Handshake message schema.
    //
    // handshake = {
    //     "action": "auth/handshake",
    //     "body": {
    //         "data": {
    //             "role": role
    //         },
    //         "method": "role_secret"
    //     },
    // }
    //
    //
    bool CobraConnection::sendHandshakeMessage()
    {
        rapidjson::Document pdu;
        pdu.SetObject();

        rapidjson::Value data;
        data.SetObject();
        data.AddMember("role",
                       rapidjson::StringRef(_roleName.c_str()),
                       pdu.GetAllocator());

        rapidjson::Value body;
        body.SetObject();
        body.AddMember("data",
                       data,
                       pdu.GetAllocator());
        body.AddMember("method",
                       "role_secret",
                       pdu.GetAllocator());

        pdu.AddMember("action",
                      "auth/handshake",
                      pdu.GetAllocator());
        pdu.AddMember("body",
                      body,
                      pdu.GetAllocator());
        pdu.AddMember("id",
                      _id++,
                      pdu.GetAllocator());

        std::string serializedJson = serializeJson(pdu);
        CobraConnection::invokeTrafficTrackerCallback(serializedJson.size(), false);

        return _webSocket->send(serializedJson).success;
    }

    //
    // Extract the nonce from the handshake response
    // use it to compute a hash during authentication
    //
    // {
    //     "action": "auth/handshake/ok",
    //     "body": {
    //         "data": {
    //             "nonce": "MTI0Njg4NTAyMjYxMzgxMzgzMg==",
    //             "version": "0.0.24"
    //         }
    //     }
    // }
    //
    bool CobraConnection::handleHandshakeResponse(const rapidjson::Document& pdu)
    {
        if (!pdu.IsObject()) return false;

        if (!pdu.HasMember("body")) return false;
        const rapidjson::Value& body = pdu["body"];

        if (!body.HasMember("data")) return false;
        const rapidjson::Value& data = body["data"];

        if (!data.HasMember("nonce")) return false;
        const rapidjson::Value& nonce = data["nonce"];

        if (!nonce.IsString()) return false;

        return sendAuthMessage(nonce.GetString());
    }

    //
    // Authenticate message schema.
    //
    // challenge = {
    //     "action": "auth/authenticate",
    //     "body": {
    //         "method": "role_secret",
    //         "credentials": {
    //             "hash": computeHash(secret, nonce)
    //         }
    //     },
    // }
    //
    bool CobraConnection::sendAuthMessage(const std::string& nonce)
    {
        rapidjson::Document pdu;
        pdu.SetObject();

        rapidjson::Value credentials;
        credentials.SetObject();
        credentials.AddMember("hash",
                              rapidjson::StringRef(hmac(nonce, _roleSecret).c_str()),
                              pdu.GetAllocator());

        rapidjson::Value body;
        body.SetObject();
        body.AddMember("credentials",
                       credentials,
                       pdu.GetAllocator());
        body.AddMember("method",
                       "role_secret",
                       pdu.GetAllocator());

        pdu.AddMember("action",
                      "auth/authenticate",
                      pdu.GetAllocator());
        pdu.AddMember("body",
                      body,
                      pdu.GetAllocator());
        pdu.AddMember("id",
                      _id++,
                      pdu.GetAllocator());

        std::string serializedJson = serializeJson(pdu);
        CobraConnection::invokeTrafficTrackerCallback(serializedJson.size(), false);

        return _webSocket->send(serializedJson).success;
    }

    bool CobraConnection::handleSubscriptionResponse(const rapidjson::Document& pdu)
    {
        if (!pdu.IsObject()) return false;

        if (!pdu.HasMember("body")) return false;
        const rapidjson::Value& body = pdu["body"];

        if (!body.HasMember("subscription_id")) return false;
        const rapidjson::Value& subscriptionId = body["subscription_id"];

        if (!subscriptionId.IsString()) return false;

        invokeEventCallback(ix::CobraConnection_EventType_Subscribed,
                            std::string(), WebSocketHttpHeaders(),
                            subscriptionId.GetString());
        return true;
    }

    bool CobraConnection::handleUnsubscriptionResponse(const rapidjson::Document& pdu)
    {
        if (!pdu.IsObject()) return false;

        if (!pdu.HasMember("body")) return false;
        const rapidjson::Value& body = pdu["body"];

        if (!body.HasMember("subscription_id")) return false;
        const rapidjson::Value& subscriptionId = body["subscription_id"];

        if (!subscriptionId.IsString()) return false;

        invokeEventCallback(ix::CobraConnection_EventType_UnSubscribed,
                            std::string(), WebSocketHttpHeaders(),
                            subscriptionId.GetString());
        return true;
    }

    bool CobraConnection::handleSubscriptionData(const rapidjson::Document& pdu)
    {
        if (!pdu.IsObject()) return false;

        if (!pdu.HasMember("body")) return false;
        const rapidjson::Value& body = pdu["body"];

        // Identify subscription_id, so that we can find
        // which callback to execute
        if (!body.HasMember("subscription_id")) return false;
        const rapidjson::Value& subscriptionId = body["subscription_id"];

        std::lock_guard<std::mutex> lock(_cbsMutex);
        auto cb = _cbs.find(subscriptionId.GetString());
        if (cb == _cbs.end()) return false; // cannot find callback

        // Extract messages now
        if (!body.HasMember("messages")) return false;
        const rapidjson::Value& messages = body["messages"];

        for (auto&& msg : messages.GetArray())
        {
            cb->second(msg);
        }

        return true;
    }

    bool CobraConnection::handlePublishResponse(const rapidjson::Document& pdu)
    {
        if (!pdu.IsObject()) return false;

        if (!pdu.HasMember("id")) return false;
        const rapidjson::Value& id = pdu["id"];

        if (!id.IsUint64()) return false;

        uint64_t msgId = id.GetUint64();

        invokeEventCallback(ix::CobraConnection_EventType_Published,
                            std::string(), WebSocketHttpHeaders(),
                            std::string(), msgId);

        invokePublishTrackerCallback(false, true);

        return true;
    }

    bool CobraConnection::connect()
    {
        _webSocket->start();
        return true;
    }

    bool CobraConnection::isConnected() const
    {
        return _webSocket->getReadyState() == ix::ReadyState::Open;
    }

    bool CobraConnection::isAuthenticated() const
    {
        return isConnected() && _authenticated;
    }

    // Use a mutex so that we don't create a StringBuffer at every serialization
    std::string CobraConnection::serializeJson(const rapidjson::Document& document)
    {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        document.Accept(writer);

        return buffer.GetString();
    }

    std::pair<CobraConnection::MsgId, std::string> CobraConnection::prePublish(
        const std::vector<std::string>& channels,
        rapidjson::Value& msg,
        bool addToQueue)
    {
        std::lock_guard<std::mutex> lock(_prePublishMutex);

        invokePublishTrackerCallback(true, false);

        CobraConnection::MsgId msgId = _id;

        rapidjson::Value channelsArray(rapidjson::kArrayType);
        // FIXME (channels)
        for (auto&& channel : channels)
        {
            channelsArray.PushBack(rapidjson::StringRef(channel.c_str()),
                                   _pdu.GetAllocator());
        }

        _body["channels"] = channelsArray;
        _body["message"] = msg;
        _pdu["body"] = _body;
        _pdu["id"] = _id++;

        std::string serializedJson = serializeJson(_pdu);

        if (addToQueue)
        {
            enqueue(serializedJson);
        }

        return std::make_pair(msgId, serializedJson);
    }

    bool CobraConnection::publishNext()
    {
        std::lock_guard<std::mutex> lock(_queueMutex);

        if (_messageQueue.empty()) return true;

        auto&& msg = _messageQueue.back();
        if (!publishMessage(msg))
        {
            return false;
        }
        _messageQueue.pop_back();
        return true;
    }

    //
    // publish is not thread safe as we are trying to reuse some Json objects.
    //
    CobraConnection::MsgId CobraConnection::publish(const std::vector<std::string>& channels,
                                                    rapidjson::Value& msg)
    {
        auto p = prePublish(channels, msg, false);
        auto msgId = p.first;
        auto serializedJson = p.second;

        //
        // 1. When we use batch mode, we just enqueue and will do the flush explicitely
        // 2. When we aren't authenticated yet to the cobra server, we need to enqueue
        //    and retry later
        // 3. If the network connection was droped (WebSocket::send will return false),
        //    it means the message won't be sent so we need to enqueue as well.
        //
        // The order of the conditionals is important.
        //
        if (_publishMode == CobraConnection_PublishMode_Batch || !_authenticated ||
            !publishMessage(serializedJson))
        {
            enqueue(serializedJson);
        }

        return msgId;
    }

    bool CobraConnection::subscribe(const std::string& channel,
                                    const std::string& filter,
                                    SubscriptionCallback cb)
    {
        rapidjson::Document pdu;
        pdu.SetObject();

        // Create and send a subscribe pdu
        rapidjson::Value body;
        body.SetObject();
        body.AddMember("channel",
                       rapidjson::StringRef(channel.c_str()),
                       pdu.GetAllocator());

        if (!filter.empty())
        {
            body.AddMember("filter",
                           rapidjson::StringRef(filter.c_str()),
                           pdu.GetAllocator());
        }

        pdu.AddMember("action",
                      "rtm/subscribe",
                      pdu.GetAllocator());
        pdu.AddMember("body",
                      body,
                      pdu.GetAllocator());
        pdu.AddMember("id",
                      _id++,
                      pdu.GetAllocator());

        // Set the callback
        std::lock_guard<std::mutex> lock(_cbsMutex);
        _cbs[channel] = cb;

        return _webSocket->send(serializeJson(pdu)).success;
    }

    bool CobraConnection::unsubscribe(const std::string& channel)
    {
        {
            std::lock_guard<std::mutex> lock(_cbsMutex);
            auto cb = _cbs.find(channel);
            if (cb == _cbs.end()) return false;

            _cbs.erase(cb);
        }

        // Create and send an unsubscribe pdu
        rapidjson::Value body;
        body["subscription_id"] = rapidjson::StringRef(channel.c_str());

        rapidjson::Document pdu;
        pdu["action"] = "rtm/unsubscribe";
        pdu["body"] = body;
        pdu["id"] = _id++;

        return _webSocket->send(serializeJson(pdu)).success;
    }

    //
    // Enqueue strategy drops old messages when we are at full capacity
    //
    // If we want to keep only 3 items max in the queue:
    //
    // enqueue(A) -> [A]
    // enqueue(B) -> [B, A]
    // enqueue(C) -> [C, B, A]
    // enqueue(D) -> [D, C, B] -- now we drop A, the oldest message,
    //                         -- and keep the 'fresh ones'
    //
    void CobraConnection::enqueue(const std::string& msg)
    {
        std::lock_guard<std::mutex> lock(_queueMutex);

        if (_messageQueue.size() == CobraConnection::kQueueMaxSize)
        {
            _messageQueue.pop_back();
        }
        _messageQueue.push_front(msg);
    }

    //
    // We process messages back (oldest) to front (newest) to respect ordering
    // when sending them. If we fail to send something, we put it back in the queue
    // at the end we picked it up originally (at the end).
    //
    bool CobraConnection::flushQueue()
    {
        while (!isQueueEmpty())
        {
            bool ok = publishNext();
            if (!ok) return false;
        }

        return true;
    }

    bool CobraConnection::isQueueEmpty()
    {
        std::lock_guard<std::mutex> lock(_queueMutex);
        return _messageQueue.empty();
    }

    bool CobraConnection::publishMessage(const std::string& serializedJson)
    {
        auto webSocketSendInfo = _webSocket->send(serializedJson);
        CobraConnection::invokeTrafficTrackerCallback(webSocketSendInfo.wireSize,
                                                      false);
        return webSocketSendInfo.success;
    }

    void CobraConnection::suspend()
    {
        disconnect();
    }

    void CobraConnection::resume()
    {
        connect();
    }

} // namespace ix

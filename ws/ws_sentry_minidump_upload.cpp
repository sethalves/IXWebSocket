/*
 *  ws_sentry_minidump_upload.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include <ixsentry/IXSentryClient.h>
#include <spdlog/spdlog.h>

namespace ix
{
    int ws_sentry_minidump_upload(const std::string& dsn,
                                  const std::string& metadataPath,
                                  const std::string& minidump,
                                  bool verbose)
    {
        SentryClient sentryClient(dsn);

        auto ret = sentryClient.uploadMinidump(metadataPath, minidump, verbose);
        HttpResponsePtr response = ret.first;
        if (response->statusCode != 200)
        {
            spdlog::error("Error sending data to sentry: {}", response->statusCode);
            spdlog::error("Body: {}", ret.second);
            spdlog::error("Response: {}", response->payload);
        }
        else
        {
            spdlog::info("Event sent to sentry");
        }

        return 0;
    }
} // namespace ix

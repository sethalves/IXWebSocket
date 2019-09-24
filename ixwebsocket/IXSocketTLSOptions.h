/*
 *  IXSocketTLSOptions.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2017-2018 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include <string>

namespace ix
{
    struct SocketTLSOptions
    {
        // pass through - validate assertions returning this object
        const SocketTLSOptions&& validated() const;

        // the certificate presented to peers
        std::string certFile;
        // the key used for signing/encryption
        std::string keyFile;
        // the ca certificate (or certificate bundle) file containing
        // certificates to be trusted by peers; use 'SYSTEM' to
        // leverage the system defaults, use 'NONE' to disable peer verification
        std::string caFile = "SYSTEM";

        std::string ciphers = "DEFAULT";

        bool hasCertAndKey() const;

        bool isUsingSystemDefaults() const;

        bool isPeerVerifyDisabled() const;

        bool isUsingDefaultCiphers() const;
    };

    // trait class to supply common tls options validation
    class TLSConfigurable
    {
    protected:
        SocketTLSOptions _tlsOptions;

    public:
        virtual void setTLSOptions(const SocketTLSOptions& tlsOptions);
    };
} // namespace ix

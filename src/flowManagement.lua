-- MIT License

-- Copyright (c) 2018 Christian Wahl

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.


-- inspired by the tuple.lua of flowscope but only filtering for tcp streams

local ffi = require "ffi"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip4 = require "proto.ip4"
local ip6 = require "proto.ip6"

ffi.cdef [[
    struct ipv4_data_tuple {
        union ip4_address ip_a; // if it is a uni-directional flow then the first is src and second dst
        union ip4_address ip_b;
        uint16_t port_a;
        uint16_t port_b;
        uint8_t  proto; // fixed to tcp, however it's included for completeness
        uint8_t ip_version;
    } __attribute__((__packed__));

    struct ipv6_data_tuple {
        union ip6_address ip_a; // if it is a uni-directional flow then the first is src and second dst
        union ip6_address ip_b;
        uint16_t port_a;
        uint16_t port_b;
        uint8_t  proto; // fixed to tcp, however it's included for completeness
        uint8_t ip_version;
    } __attribute__((__packed__));
]]

local module = {}

module.flowKeys = {
    "struct ipv4_data_tuple",
    "struct ipv6_data_tuple"
}

module.IPv4_FLOW = 1
module.IPv6_FLOW = 2

local ipv4_tuple = {}
local ipv6_tuple = {}

local ip_string_template = "IP_tuple: {version: %s, protocol: %s, ip_a: %s, port_a: %u, ip_b: %s, port_b: %u}"
local pflang_template_bi = "%s proto \\%s and host %s and port %u and host %s and port %u" -- the first string is either a ip or ip6 (for IPv6)
local pflang_template_uni = "%s proto \\%s src host %s and src port %u and dst host %s and dst port %u" -- the first string is either a ip or ip6 (for IPv6)


-- parameter ip_version: either 4 or 6 determining the used ip_version

local function convert_protocol_number_to_string(ip_version, protocol_number)
    local l4_proto = "unknown"
    if ip_version == 4 and protocol_number == ip4.PROTO_TCP then
        l4_proto = "tcp"
    elseif ip_version == 6 and protocol_number == ip6.PROTO_TCP then
        l4_proto = "tcp"
    end
    return l4_proto
end

local function versioned_to_string (ip_version)
    local function to_string(packet)
        local proto = convert_protocol_number_to_string(ip_version, packet.proto)
        return ip_string_template:format(ip_version, proto, packet.ip_a:getString(), packet.port_a,packet.ip_b:getString(), packet.port_b)
    end
    return to_string
end

function ipv4_tuple:__tostring()
    return versioned_to_string(4)(self)
end

function ipv6_tuple:__tostring()
    return versioned_to_string(6)(self)
end

local function versioned_get_pflang(ip_version, template)
    local l3_proto = "ip6"
    if ip_version == 4 then
        l3_proto = "ip"
    end
    local function get_pflang(packet)
        local proto = convert_protocol_number_to_string(ip_version, packet.proto)
        return template:format(l3_proto, proto, packet.ip_a:getString(), packet.port_a,packet.ip_b:getString(), packet.port_b)
    end
    return get_pflang
end

function ipv4_tuple:getPflangBi()
    return versioned_get_pflang(4, pflang_template_bi)(self)
end

function ipv6_tuple:getPflangBi()
    return versioned_get_pflang(6, pflang_template_bi)(self)
end

function ipv4_tuple:getPflangUni()
    return versioned_get_pflang(4, pflang_template_uni)(self)
end

function ipv6_tuple:getPflangUni()
    return versioned_get_pflang(6, pflang_template_uni)(self)
end

ipv4_tuple.__index = ipv4_tuple
ipv6_tuple.__index = ipv6_tuple

ffi.metatype("struct ipv4_data_tuple", ipv4_tuple)
ffi.metatype("struct ipv6_data_tuple", ipv6_tuple)


-- general functions to extract the 5 tuple
function module.extract5TupleUnidirectional(buf, keyBuf)
    local eth_paket = pktLib.getEthernetPacket(buf)
    local eth_type = eth_paket.eth:getType()
    if eth_type == eth.TYPE_IP then
        keyBuf = ffi.cast("struct ipv4_data_tuple&", keyBuf)
        local packet = pktLib.getTcp4Packet(buf)
        keyBuf.ip_a.uint32 = packet.ip4.src.uint32
        keyBuf.ip_b.uint32 = packet.ip4.dst.uint32
        keyBuf.port_a = packet.tcp:getSrcPort()
        keyBuf.port_b = packet.tcp:getDstPort()
        keyBuf.proto = packet.ip4:getProtocol()
        keyBuf.ip_version = 4
        if keyBuf.proto == ip4.PROTO_TCP then
            return true, 1
        end
    elseif eth_type == eth.TYPE_IP6 then
        keyBuf = ffi.cast("struct ipv6_data_tuple&", keyBuf)
        local packet = pktLib.getTcp6Packet(buf)
        keyBuf.ip_a.uint64[0] = packet.ip6.src.uint64[0]
        keyBuf.ip_a.uint64[1] = packet.ip6.src.uint64[1]
        keyBuf.ip_b.uint64[0] = packet.ip6.dst.uint64[0]
        keyBuf.ip_b.uint64[1] = packet.ip6.dst.uint64[1]
        keyBuf.port_a = packet.tcp:getSrcPort()
        keyBuf.port_b = packet.tcp:getDstPort()
        keyBuf.proto = packet.ip6:getProtocol()
        keyBuf.ip_version = 6
        if keyBuf.proto == ip6.PROTO_TCP then
            return true, 2
        end
    end
    return false
end

function module.extract5TupleBidirectional(buf, keyBuf)
    local success, flow_type = module.extract5TupleUnidirectional(buf, keyBuf)
    if success and flow_type == module.IPv4_FLOW then
        keyBuf = ffi.cast("struct ipv4_data_tuple&", keyBuf)
        if keyBuf.ip_a.uint32 < keyBuf.ip_b.uint32 then
            keyBuf.ip_a.uint32, keyBuf.ip_b.uint32 = keyBuf.ip_b.uint32, keyBuf.ip_a.uint32
            keyBuf.port_a, keyBuf.port_b = keyBuf.port_b, keyBuf.port_a
        end
        return success, flow_type
    elseif success and flow_type == module.IPv6_FLOW then
        if keyBuf.ip_a < keyBuf.ip_b then
            keyBuf.ip_a, keyBuf.ip_b = keyBuf.ip_b:get(), keyBuf.ip_a:get()
            keyBuf.port_a, keyBuf.port_b = keyBuf.port_b, keyBuf.port_a
        end
        return success, flow_type
    end
    return false
end

return module
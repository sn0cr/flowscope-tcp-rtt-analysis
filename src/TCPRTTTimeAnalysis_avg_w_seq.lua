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

local function script_path()
    local str = debug.getinfo(2, "S").source:sub(2)
    return str:match("(.*/)")
end
package.path = script_path() .. "/?.lua;" .. package.path

-- libraries of flowscope
local ffi = require "ffi"
local lm = require "libmoon"
local log = require "log"
local pktLib = require "packet"
-- local libraries
local json = require "json"
local tracker = require "flowManagement"
local module = {}

-- flow tracker configuration
local JSON_PATH_PREFIX = "./json/"

module.number_of_sequences = 11

-- the state type can only be 128B in size! (see the hmap.lua in flowscope/lua folder)

ffi.cdef [[
    struct timestamped_tuple {
        uint32_t sequence_number;
        uint32_t timestamp;
    };
    struct flow_state {
        uint32_t byte_counter;
        uint32_t packet_counter;
        uint64_t last_seen;
        // 16 B
        double avg_rtt;
        // 24B
        uint32_t max_rtt;
        uint32_t min_rtt;
        uint8_t tracked;
        uint8_t rtt_index;
        // 34
        // each struct is 8B
        // => 128B - 34B=94B
        // => 94B / 8B= 11.75 => 11 Sequences
        struct timestamped_tuple rtts[11];
    };
]]

module.mode = "qq"

-- Flow keys: Position in the array corresponds to the index returned by extractFlowKey()
module.flowKeys = tracker.flowKeys
-- This function extracts the flowKey from a packet (here: the 5-tuple)
module.extractFlowKey = tracker.extract5TupleUnidirectional

-- Name the flow state type
module.stateType = "struct flow_state"

module.defaultState = {}

-- expiry time: time after which a flow is seen as ended
module.expiryTime = 60 -- in seconds

module.time_multiplier = 10 ^ 9 -- multiplier to get the timestamp in ns

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local function store_in_buffer(sequence_number, timestamp)
        -- first store in buffer
        local index = state.rtt_index % module.number_of_sequences
        state.rtts[index].sequence_number = sequence_number
        state.rtts[index].timestamp = timestamp
        state.rtt_index = state.rtt_index + 1
    end

    -- lm.getTime() is sourced from the same clock (TSC) and can be directly compared to these
    local ts = buf:getTimestamp() * module.time_multiplier -- ns
    state.packet_counter = state.packet_counter + 1
    state.byte_counter = state.byte_counter + buf:getSize()

    local packet = nil
    if flowKey.ip_version == 4 then
        packet = pktLib.getTcp4Packet(buf)
    elseif flowKey.ip_version == 6 then
        packet = pktLib.getTcp6Packet(buf)
    else
        log:warn("[Tracker]: Got unrecognized ip_version")
        return false
    end

    if isFirstPacket then
        store_in_buffer(packet.tcp:getSeqNumber(), ts)
    else
        local ack_seq = packet.tcp:getAckNumber() - 1
        local found_index = -1
        for i=0, module.number_of_sequences do
            if state.rtts[i].sequence_number == ack_seq then
                found_index = i
                break
            end
        end

        if packet.tcp:getAck() and found_index > -1 then
            local rtt = ts - state.rtts[found_index].timestamp
            store_in_buffer(packet.tcp:getSeqNumber(), ts)
            -- compute the avg rtt
            state.avg_rtt = (state.avg_rtt + tonumber(rtt)) / 2
            if state.max_rtt < rtt then
                state.max_rtt = rtt
            end
            if state.min_rtt > rtt then
                state.min_rtt = rtt
            end
        else
            -- the ack bit is not set
            store_in_buffer(packet.tcp:getSeqNumber(), ts)
        end
    end
    state.last_seen = ts
    if state.tracked == 1 then
        return false
    else
        state.tracked = 1
        return true
    end
end

-- #### Checker configuration ####
-- set to nil / do not define it to disable the checker
module.checkInterval = module.expiryTime / 2

-- initial state for the checker thread
module.checkState = {start_time = 0}

-- from flowscopes ExampleModule.lua:
-- Function that gets called in regular intervals to decide if a flow is still active.
-- Returns false for active flows.
-- Returns true and a timestamp in seconds for flows that are expired.
function module.checkExpiry(flowKey, state, checkState)
    -- can be used to write the data out
    local t = lm.getTime()
    local last = tonumber(state.last_seen) / module.time_multiplier -- Convert back to seconds
    if last + module.expiryTime < t then
        local info_map = {
            source_ip = flowKey.ip_a:getString(),
            destination_ip = flowKey.ip_b:getString(),
            source_port = tonumber(flowKey.port_a),
            destination_port = tonumber(flowKey.port_b),
            ip_version = tonumber(flowKey.ip_version),
            min_rtt = tonumber(state.min_rtt),
            max_rtt = tonumber(state.max_rtt),
            avg_rtt = tonumber(state.avg_rtt),
            packet_counter = tonumber(state.packet_counter),
            byte_counter = tonumber(state.byte_counter)
        }
        local json_string = json.encode(info_map)
        local file_name = JSON_PATH_PREFIX .. "%s_%s.json"
        file_name = file_name:format(flowKey.ip_a:getString(), flowKey.ip_b:getString())
        local file = io.open(file_name, "a")
        file:write(json_string)
        file:close()
        return true, last
    end
    return false
end

-- This function is called before any packets are received and one time per checker thread
function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * module.time_multiplier
end

-- This function is called just before the checker thread will terminate (-> for clean up)
function module.checkFinalizer(checkState, keptFlows, purgedFlows)
    local t = lm.getTime() * module.time_multiplier
    log:info(
        "[Checker]: Done, took %fs, flows %i/%i/%i [purged/kept/total]",
        (t - tonumber(checkState.start_time)) / module.time_multiplier,
        purgedFlows,
        keptFlows,
        purgedFlows + keptFlows
    )
end

-- #### Dumper configuration ####

module.maxDumperRules = 2 ^ 13
function module.buildPacketFilter(flowKey)
    return flowKey:getPflangUni()
end

return module

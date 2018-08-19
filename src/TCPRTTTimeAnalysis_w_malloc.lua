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

-- get path to this script in order to add other lua scripts along the user module to the lua path
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

-- ############ CONFIGURATION SECTION ############
-- flow tracker configuration
local JSON_PATH_PREFIX = "./json/" -- the folder in which we want to put the json files (relative to current working directory)

ffi.cdef [[
    struct List_node {
        uint32_t sequence_number;
        uint32_t timestamp;
        struct List_node* next;
        struct List_node* prev;
    };

    struct RTT_List {
        uint32_t rtt;
        struct RTT_List* next;
        struct RTT_List* prev;
    };

    struct flow_state {
        uint32_t byte_counter;
        uint32_t packet_counter;
        uint64_t last_seen;
        uint32_t max_rtt;
        uint32_t min_rtt;
        uint8_t tracked;
        struct List_node* seq_list;
        struct List_node* ack_list;
        struct RTT_List* rtts;
    };
    void *malloc(size_t size);
    void free(void *ptr);
]]

module.seq_list_type = "struct List_node"
module.rtt_list_type = "struct RTT_List"

module.mode = "qq"

-- Flow keys: Position in the array corresponds to the index returned by extractFlowKey()
module.flowKeys = tracker.flowKeys
-- This function extracts the flowKey from a packet (here: the 5-tuple)
module.extractFlowKey = tracker.extract5TupleBidirectional

-- Name the flow state type
module.stateType = "struct flow_state"

module.defaultState = {seq_list = nil, rtts = nil, ack_list = nil} -- rest should be 0 by default

-- expiry time: time after which a flow is seen as ended
module.expiryTime = 60 -- in seconds

module.time_multiplier = 10 ^ 9 -- multiplier to get the timestamp in ns

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local function get_pointer(typestr)
        -- source (adapted): https://stackoverflow.com/questions/24112779/how-can-i-create-a-pointer-to-existing-data-using-the-luajit-ffi
        -- automatically construct the pointer type from the base type
        local ptr_typestr = ffi.typeof(typestr .. " *")
        -- how many bytes to allocate?
        local typesize = ffi.sizeof(typestr)
        -- do the allocation and cast the pointer result
        local ptr = ffi.cast(ptr_typestr, ffi.C.malloc(typesize))
        return ptr
    end

    local function add_to_list(sequence_number, timestamp)
        -- first create new node:
        -- automatically construct the pointer type from the base type
        local node = get_pointer(module.seq_list_type)
        node.sequence_number = sequence_number
        node.timestamp = timestamp
        node.next = nil
        node.prev = nil
        -- append to list
        if state.seq_list ~= nil then
            node.next = state.seq_list
            state.seq_list.prev = node
        end
        state.seq_list = node
    end

    local function add_ack_to_list(sequence_number, timestamp)
        -- first create new node:
        -- automatically construct the pointer type from the base type
        local node = get_pointer(module.seq_list_type)
        node.sequence_number = sequence_number
        node.timestamp = timestamp
        node.next = nil
        node.prev = nil
        -- append to list
        if state.ack_list ~= nil then
            node.next = state.ack_list
            state.ack_list.prev = node
        end
        state.ack_list = node
    end

    local function store_rtt(rtt)
        local node = get_pointer(module.rtt_list_type)
        node.rtt = rtt
        node.next = nil
        node.prev = nil
        -- append to list
        if state.rtts ~= nil then
            node.next = state.rtts
            state.rtts.prev = node
        end
        state.rtts = node
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
        add_to_list(packet.tcp:getSeqNumber(), ts)
    else
        local ack_seq = packet.tcp:getAckNumber() - 1

        -- iterate over list and search for seq num
        local seq_node = nil
        local current_node = state.seq_list
        while current_node.next ~= nil do
            if current_node.sequence_number == ack_seq then
                seq_node = current_node
                break
            else
                current_node = current_node.next
            end
        end
        if packet.tcp:getAck() and seq_node ~= nil then
            -- ack flag is set and we found a syn package
            add_ack_to_list(packet.tcp:getAckNumber(), ts)
            local rtt = ts - seq_node.timestamp
            -- compute the avg rtt
            -- state.avg_rtt = (state.avg_rtt + tonumber(rtt)) / 2
            store_rtt(rtt)
            if state.max_rtt < rtt then
                state.max_rtt = rtt
            end
            if state.min_rtt > rtt then
                state.min_rtt = rtt
            end
        end
        -- add the seq number and the time stamp to the list as this packet is not ack'ed
        add_to_list(packet.tcp:getSeqNumber(), ts)
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
        -- free syn list
        local seq_list = {}
        local current_node = state.seq_list
        while current_node ~= nil and current_node.next ~= nil do
            local seq_node = current_node
            seq_list[#seq_list + 1] = {sequence_number = tonumber(current_node.sequence_number), timestamp = tonumber(current_node.timestamp)}
            -- remove the node
            ffi.C.free(seq_node)
            current_node = current_node.next
        end
        state.seq_list = nil
        local ack_list = {}
        local current_node = state.ack_list
        while current_node ~= nil and current_node.next ~= nil do
            local ack_node = current_node
                ack_list[#ack_list + 1] = {sequence_number = tonumber(current_node.sequence_number), timestamp = tonumber(current_node.timestamp)}
            -- remove the node
            ffi.C.free(ack_node)
            current_node = current_node.next
        end
        state.ack_list = nil
        -- create a list out of the linked list
        local rtt_list = {}
        local last_node = state.rtts
        -- mind that the order is reversed!
        if last_node ~= nil then
            while last_node ~= nil and last_node.next ~= nil do
                last_node = last_node.next
            end
            while last_node.prev ~= nil do
                -- remove the node
                rtt_list[#rtt_list+1]= tonumber(last_node.rtt)
                ffi.C.free(last_node)
                last_node = last_node.prev
            end
        end
        local info_map = {
            source_ip = flowKey.ip_a:getString(),
            destination_ip = flowKey.ip_b:getString(),
            source_port = tonumber(flowKey.port_a),
            destination_port = tonumber(flowKey.port_b),
            ip_version = tonumber(flowKey.ip_version),
            min_rtt = tonumber(state.min_rtt),
            max_rtt = tonumber(state.max_rtt),
            packet_counter = tonumber(state.packet_counter),
            byte_counter = tonumber(state.byte_counter),
            rtts = rtt_list,
            seq_list = seq_list,
            ack_list = ack_list
        }
        local json_string = json.encode(info_map)
        local file_name = JSON_PATH_PREFIX .. "%s_%s.json"
        file_name = file_name:format(flowKey.ip_a:getString(), flowKey.ip_b:getString())
        local file = io.open(file_name, "a")
        file:write(json_string)
        file:write("\n")
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

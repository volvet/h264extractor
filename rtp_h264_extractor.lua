
--[[
 * rtp_h264_extractor.lua
 * wireshark plugin to extract h264 stream from RTP packets
 * 
 * Copyright (C) 2015 Volvet Zhang <volvet2002@gmail.com>
 *
 * rtp_h264_extractor is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * rtp_h264_extractor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *]]


do
    local MAX_JITTER_SIZE = 50
    local h264_data = Field.new("h264")
    local rtp_seq = Field.new("rtp.seq")
	
    local function extract_h264_from_rtp()
        local h264_tap = Listener.new("ip", "h264")
        local text_window = TextWindow.new("h264 extractor")
        local fp = io.open("dump.264", "wb")
        local seq_payload_table = { }
        local pass = 0
        local packet_count = 0
        local max_packet_count = 0
        local fu_info = nil
		
        local function log(info)
            text_window:append(info)
            text_window:append("\n")
        end
        
        if fp == nil then 
            log("open dump file fail")
        end
        
        local function seq_compare(left, right)  
            if math.abs(right.key - left.key) < 1000 then  
                return left.key < right.key  
            else 
                return left.key > right.key  
            end  
        end  
        
        local function dump_single_nal(h264_payload)
            fp:write("\00\00\00\01")
            fp:write(h264_payload:tvb()():raw())
            fp:flush()
        end
        
        local function dump_fu_a(fu_info) 
            if  fu_info.complete ==  true then 
                log("dump_fu_a")
                fp:write("\00\00\00\01")
                fp:write(string.char(fu_info.nal_header))
            
                for i, obj in ipairs(fu_info.payloads) do
                    fp:write(obj:tvb()():raw(2))
                end
                fp:flush()
            else
                log("Incomplete NAL from FUs, dropped")
            end
        end
        
        local function handle_fu_a(seq, h264_data)
            fu_indicator = h264_data:get_index(0)
            fu_header = h264_data:get_index(1)
            nal_header = bit.bor(bit.band(fu_indicator, 0xe0), bit.band(fu_header, 0x1f))
            
            if bit.band(fu_header, 0x80) ~= 0 then
                -- fu start flag found
                fu_info = { }
                fu_info.payloads = { }
                fu_info.seq = seq
                fu_info.complete = true
                fu_info.nal_header = nal_header
                
                table.insert(fu_info.payloads, h264_data)
                log("Fu start: seq = "..tostring(seq))
                return
            end
            
            if fu_info == nil then 
                log("Incomplete FU found: No start flag, dropped")
                return
            end
            
            if seq ~= (fu_info.seq + 1)% 65536 then
                log("Incomplete FU found:  fu_info.seq = "..tostring(fu_info.seq)..", input seq = "..tostring(seq))
                fu_info.complete = false;
                return
            end
            
            fu_info.seq = seq
            
            table.insert(fu_info.payloads, h264_data)
            
            if bit.band(fu_header, 0x40) ~= 0 then
                -- fu end flag found
                log("Fu stop: seq = "..tostring(seq))
                dump_fu_a(fu_info)
                fu_info = nil
            end 
            
        end
        
        local function handle_stap_a(h264_data)
            log("start dump stap nals")
            offset = 1		-- skip nal header of STAP-A
            repeat
                size = h264_data:tvb()(offset, 2):uint()
                offset = offset + 2
                local next_nal_type = bit.band(h264_data:get_index(offset), 0x1f)
                log("STAP-A has naltype = "..next_nal_type..", size = "..size)
                fp:write("\00\00\00\01")
                fp:write(h264_data:tvb()():raw(offset, size))
                offset = offset + size
            until offset >= h264_data:tvb():len()
            fp:flush()
            log("finish dump stap nals")
        end
		
        local function on_ordered_h264_payload(seq, h264_data)
            local naltype = bit.band(h264_data:get_index(0), 0x1f)
            if naltype > 0 and naltype < 24 then 
                -- Single NAL unit packet
                if fu_info ~= nil then
                    log("Incomplete FU found: No start flag, dropped")
                    fu_info = nil
                end
                dump_single_nal(h264_data)
                --log("tap.packet: "..", single nal packet dumpped, naltype = "..tostring(naltype)..", len = "..tostring(packet.len))
            elseif naltype == 28 then
                -- FU-A
                handle_fu_a(seq, h264_data)
            elseif naltype == 24 then
                -- STAP-A
                if fu_info ~= nil then
                    log("Incomplete FU found: No start flag, dropped")
                    fu_info = nil
                end
                handle_stap_a(h264_data)
            else
                log("tap.packet: "..", Unsupported nal, naltype = "..tostring(naltype))				
            end 
        end
        
        local function on_jitter_buffer_output()
            table.sort(seq_payload_table, seq_compare)
            
            if #seq_payload_table > 0 then
                log("on_jitter_buffer_output:  seq = "..tostring(seq_payload_table[1].key)..", payload len = "..tostring(seq_payload_table[1].value:len()))
                on_ordered_h264_payload(seq_payload_table[1].key, seq_payload_table[1].value)
                table.remove(seq_payload_table, 1)
            end
        end
        
        local function jitter_buffer_finilize() 
            for i, obj in ipairs(seq_payload_table) do
                log("jitter_buffer_finilize:  seq = "..tostring(obj.key)..", payload len = "..tostring(obj.value:len()))
                on_ordered_h264_payload(obj.key, obj.value)
            end
        end
        
        local function on_h264_rtp_payload(seq, payload)
            --log("on_h264_rtp_payload:  seq = "..tostring(seq.value)..", payload len = "..tostring(payload.len))
            table.insert(seq_payload_table, { key = tonumber(seq.value), value = payload.value })
            
            --log("on_h264_rtp_payload: table size is "..tostring(#seq_payload_table))
            if #seq_payload_table > MAX_JITTER_SIZE then
                on_jitter_buffer_output()
            end
        end
        
        function h264_tap.packet(pinfo, tvb)
            local payloadTable = { h264_data() }
            local seqTable = { rtp_seq() }
            
            if (#payloadTable) < (#seqTable) then 
                log("ERROR: payloadTable size is "..tostring(#payloadTable)..", seqTable size is "..tostring(#seqTable))
                return
            end
            
            if pass == 0 then 
                for i, payload in ipairs(payloadTable) do
                    max_packet_count = max_packet_count + 1
                end
            else 
                packet_count = packet_count + 1
                
                for i, payload in ipairs(payloadTable) do
                    on_h264_rtp_payload(seqTable[1], payload)
                end
                
                if packet_count == max_packet_count then
                    jitter_buffer_finilize()
                end
            end 
        end
		
        function h264_tap.reset()
        end
		
        function h264_tap.draw() 
        end
		
        local function remove() 
            if fp then 
                fp:close()
                fp = nil
            end
            h264_tap:remove()
        end 
		
        log("Start")
		
        text_window:set_atclose(remove)
		
        log("phase 1")
        pass = 0
        retap_packets()
        
        log("phase 2:  max_packet_count = "..tostring(max_packet_count))
        pass = 1
        retap_packets()
		
        log("End")
	end


	register_menu("Extract h264 stream from RTP", extract_h264_from_rtp, MENU_TOOLS_UNSORTED)
end
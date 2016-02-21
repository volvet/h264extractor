--[[
 * rtp_opus_extractor.lua
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
    local rtp_payload = Field.new("rtp.payload")
    local rtp_seq = Field.new("rtp.seq")
    
    local function extract_opus_from_rtp()
        local opus_tap = Listener.new("ip")
        local text_window = TextWindow.new("opus extractor")
        local fp = io.open("dump.opus", "wb")
        local seq_payload_table = { }
        local packet_count = 0
        local max_packet_count = 0;
        local pass = 0;
    
        local function log(info)
            text_window:append(info)
            text_window:append("\n")
        end
        
        local function remove() 
            if fp then 
                fp:close()
                fp = nil
            end
            opus_tap:remove()
        end
        
        local function seq_compare(left, right)  
            if math.abs(right.key - left.key) < 1000 then  
                return left.key < right.key  
            else 
                return left.key > right.key  
            end  
        end
        
        local function writebytes(f,x)
            local b1=string.char(x%256) x=(x-x%256)/256
            local b2=string.char(x%256) x=(x-x%256)/256
            local b3=string.char(x%256) x=(x-x%256)/256
            local b4=string.char(x%256) x=(x-x%256)/256
            f:write(b1,b2,b3,b4)
        end
        
        local function on_ordered_opus_payload(seq, opus_data)
            length = opus_data:tvb():len()
            --log("Opus packet length = "..tostring(length).."formated:"..string.format("%04x", length))         
            writebytes(fp, length)
            fp:write(opus_data:tvb()():raw())
            fp:flush()
        end
        
        local function on_jitter_buffer_output()
            table.sort(seq_payload_table, seq_compare)
            
            if #seq_payload_table > 0 then
                log("on_jitter_buffer_output:  seq = "..tostring(seq_payload_table[1].key)..", payload len = "..tostring(seq_payload_table[1].value:len()))
                on_ordered_opus_payload(seq_payload_table[1].key, seq_payload_table[1].value)
                table.remove(seq_payload_table, 1)
            end
        end
        
        local function jitter_buffer_finilize() 
            for i, obj in ipairs(seq_payload_table) do
                log("jitter_buffer_finilize:  seq = "..tostring(obj.key)..", payload len = "..tostring(obj.value:len()))
                on_ordered_opus_payload(obj.key, obj.value)
            end
        end
        
        local function on_opus_payload(seq, payload)
            --log("on_opus_payload:  seq = "..tostring(seq.value)..", payload len = "..tostring(payload.len))
            table.insert(seq_payload_table, { key = tonumber(seq.value), value = payload.value })
            
            --log("on_opus_payload: table size is "..tostring(#seq_payload_table))
            if #seq_payload_table > MAX_JITTER_SIZE then
                on_jitter_buffer_output()
            end
        end
        
        
        function opus_tap.packet(pinfo, tvb)
            local payloadTable = { rtp_payload() }
            local seqTable = { rtp_seq() }
            
            if (#payloadTable) ~= (#seqTable) then 
                log("ERROR: payloadTable size is "..tostring(#payloadTable)..", seqTable size is "..tostring(#seqTable))
                return
            end
            
            if pass == 0 then 
                for i, payload in ipairs(payloadTable) do
                    max_packet_count = max_packet_count + 1
                end
            else
                for i, payload in ipairs(payloadTable) do
                    packet_count = packet_count + 1
                    on_opus_payload(seqTable[i], payload)
                end
                
                if packet_count == max_packet_count then 
                    jitter_buffer_finilize()
                end
            end 
        end
        
        function opus_tap.reset()
        end
		
        function opus_tap.draw() 
        end
        
        log("Start")
		
        text_window:set_atclose(remove)
        
        pass = 0
        retap_packets()
        log("phase 1 max_packet_count = "..tostring(max_packet_count))
        
        pass = 1
        retap_packets()
        
        log("End")
        
    end
  
    register_menu("Extract opus stream from RTP", extract_opus_from_rtp, MENU_TOOLS_UNSORTED)
end
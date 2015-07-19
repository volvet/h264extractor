
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
    local h264_data = Field.new("h264")
	
    local function extract_h264_from_rtp()
		local h264_tap = Listener.new("ip")
		local text_window = TextWindow.new("h264 extractor")
		local packet_count = 0
		local fp = io.open("dump.264", "wb")
		
		if fp == nil then 
		    log("open dump file fail")
		end
		
		local function log(info)
		    text_window:append(info)
			text_window:append("\n")
		end
		
		local function dump_single_nal(h264_payload)
		    fp:write("\00\00\00\01")
			fp:write(h264_payload:tvb()():raw())
			fp:flush()
		end
		
		function h264_tap.packet(pinfo, tvb)
		    local packetTable = { h264_data() }
			
			for i, packet in ipairs(packetTable) do 
			    local h264_payload = packet.value
				local naltype = bit.band(h264_payload:get_index(0), 0x1f)
			    packet_count = packet_count + 1
				if naltype > 0 and naltype < 24 then 
				    -- Single NAL unit packet
					dump_single_nal(h264_payload)
					log("tap.packet: "..tostring(packet_count)..", single nal packet dumpped, naltype = "..tostring(naltype)..", len = "..tostring(packet.len))
				elseif naltype == 28 then
                    -- FU-A
					log("tap.packet: "..tostring(packet_count)..", Unsupported nal, naltype = "..tostring(naltype))
				elseif naltype == 24 then
				    -- STAP-A
					log("tap.packet: "..tostring(packet_count)..", Unsupported nal, naltype = "..tostring(naltype))
				else
                    log("tap.packet: "..tostring(packet_count)..", Unsupported nal, naltype = "..tostring(naltype))				
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
		
		retap_packets()
		
		log("End")
	end


	register_menu("Extract h264 stream from RTP", extract_h264_from_rtp, MENU_TOOLS_UNSORTED)
end
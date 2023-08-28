while true do
	local hour = mainmemory.read_u16_le(0x028FA1);
	local minute = mainmemory.read_u16_le(0x028FA2);
	local time = "";
	if (hour > 9) then
		time = tostring(hour)..":";
	else
		time = "0"..tostring(hour)..":";
	end
	if (minute > 9) then
		time = time..tostring(minute);
	else
		time = time.."0"..tostring(minute);
	end
	gui.drawText(10, 10, time);

	local nextMinute =  mainmemory.read_u16_le(0x028FB2);
	if (nextMinute < minute) then
		nextMinute = (nextMinute + 60) - minute;
	else
		nextMinute = nextMinute - minute;
	end
	local nextTime = "  +";
	if (nextMinute > 9) then
		nextTime = nextTime..tostring(nextMinute);
	else
		nextTime = nextTime.."0"..tostring(nextMinute);
	end
	gui.drawText(10, 25, nextTime);
	emu.frameadvance();
end

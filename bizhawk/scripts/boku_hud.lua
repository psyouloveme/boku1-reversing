while true do
    -- time display by psyouloveme
    local hour = mainmemory.readbyte(0x028FA1);
    local minute = mainmemory.readbyte(0x028FA2);
    local day = mainmemory.readbyte(0x028fb0);
    local time = bizstring.pad_start(tostring(hour), 2, 0)..":"..bizstring.pad_start(tostring(minute), 2, 0).." aug "..bizstring.pad_start(tostring(day), 2, 0);
    gui.drawText(10, 0, time);

    local nextMinute =  mainmemory.readbyte(0x028FB2);
    if (nextMinute < minute) then
        nextMinute = (nextMinute + 60) - minute;
    else
        nextMinute = nextMinute - minute;
    end
    
    local nextTimeIncrementText = "  +"..bizstring.pad_start(tostring(nextMinute), 2, 0);
    gui.drawText(10, 10, nextTimeIncrementText);
    
    -- storypoints display by Ted and psyouloveme
    
    local pointsraw = mainmemory.readbyte(0x035f35); -- found by PS
    local points = 0;
    local point_to_draw = 0;
    local point_name = "";
  
    for i = 0, 15 do
        if ((pointsraw & (1 << i)) ~= 0) then
            point_to_draw = i + 1;
            point_ypos = 30 + (points * 10);
            if point_to_draw == 3 then
                point_name = " - corn";
            elseif point_to_draw == 4 then
                point_name = " - moe 1";
            elseif point_to_draw == 5 then
                point_name = " - moe 2";
            elseif point_to_draw == 6 then
                point_name = " - shirabe 1";
            elseif point_to_draw == 7 then
                point_name = " - shirabe 2";
            elseif point_to_draw == 8 then
                point_name = " - ??? fish ?? flowers??";
            elseif point_to_draw == 12 then
                point_name = " - fireflies";
            elseif point_to_draw == 14 then
                point_name = " - snake skin";
            elseif point_to_draw == 15 then
                point_name = " - shirabe 3";
            elseif point_to_draw == 16 then
                point_name = " - rain";
            else            
                point_name = " - unknown";
            end
            gui.drawText(10, point_ypos, point_to_draw..point_name);
            points = points + 1;
        end
    end
    
    if (points > 12) then
        gui.drawText(10, 20, "writer");
    elseif (points > 9) then
        gui.drawText(10, 20, "potter");
    elseif (points > 6) then
        gui.drawText(10, 20, "marriage");
    elseif (points > 3) then
        gui.drawText(10, 20, "programmer");
    end
    if (points > 0) then

        local points_text_bin = bizstring.pad_start(bizstring.binary(pointsraw), 16, 0);
        local points_text_hex = bizstring.pad_start(bizstring.hex(pointsraw), 4, 0).."h";
        gui.drawText(160, 0, "0x035f35");
        gui.drawText(160, 10, points_text_bin);
        gui.drawText(160, 20, points_text_hex);
    end

    -- local hivehits = mainmemory.readbyte(0x035EE3);
	-- gui.drawText(160, 30, "beehive hits: "..tostring(hivehits));
    -- local treehitsone = mainmemory.readbyte(0x035E91);
	-- gui.drawText(160, 40, "tree hits: "..tostring(treehitsone));

    emu.frameadvance();
end
---do this dumb workaround to get typing for the global
_G.mainmemory = _G.mainmemory
_G.bizstring = _G.bizstring
_G.emu = _G.emu
_G.joypad = _G.joypad
_G.gui = _G.gui

local mode_offset = 0x237e0;
local GAME_MODE = 0;

local bugStructSize   = 0xc;

-- arrays of 20
local fatBugArray     = 0x3db38;
local glassesBugArray = 0x3dc28;
local gutsBugArray    = 0x3dd20;

-- array of 30
local bugArray        = 0x3de18;

-- one bug
local singleBug       = 0x3df80;
local singleBugTwo    = 0x3e098;

-- array of 10
local bokuBugArray    = 0x45a10;

-- one bug
local singleBugThree  = 0x46f08;
local singleBugFour   = 0x46f18;

-- array of 150
local bigBugStruct    = 0x46f28;
local singleBugFive   = 0x47c08;

-- time and maps
local hour_offset = 0x028FA1;
local minute_offset = 0x028FA2;
local day_offset = 0x028fb0;
local map_offset = 0x26c00;
local next_minute_offset = 0x028FB2;
local next_map_offset = 0x26c08;
local luck_offset = 0x3dd1d;

-- sumo basic stats
local sumo_level_offset = 0x3d278;
local sumo_wins_offset = 0x3d279;

-- sumo match info
local sumo_player_beetle_offset = 0x8f028;
local sumo_opponent_beetle_offset = 0x8f098;

-- last CD POS
local cdpos_last_minute_offset = 0x025A40;
local cdpos_last_second_offset = 0x025A41;
local cdpos_last_sector_offset = 0x025A42;

-- story point bitfield
local story_point_offset = 0x035f35;

-- beehive hits
local beehive_hit_today_offset = 0x035EE2;
local beehive_total_hit_offset = 0x035EE3;

-- tree hit status
local tree_hits_offset = 0x035E91;

-- flowers
local water_level_offset = 0x035E92;
local blooms_offset = 0x035E93;
local watered_today_offset = 0x035E4E;



---Convert CD Pos to Int
---@param minute number
---@param second number
---@param sector number
---@return number
local function cdPosToInt(minute, second, sector)
    return (((minute >> 4) * 10 + (minute & 15)) * 60 + (second >> 4) * 10 + (second & 15)) * 75 + (sector >> 4) * 10 + (sector & 15) + -150;
end

---Convert Int to CD Pos table
---@param cdint number
---@return table
local function cdIntToPos(cdint)
    local pos = {
        minute = nil,
        second = nil,
        sector = nil
    };
    local iVar1;
    local iVar2;
    local iVar3;
    iVar3 = math.floor((cdint + 150) / 75);
    iVar2 = (cdint + 150) % 75;
    iVar1 = math.floor(iVar3 / 60);
    iVar3 = iVar3 % 60;
    pos.sector = iVar2 + math.floor(iVar2 / 10) * 6;
    pos.second = iVar3 + math.floor(iVar3 / 10) * 6;
    pos.minute = iVar1 + math.floor(iVar1 / 10) * 6;
    return pos;
end

---Read a string from memory
---by psyouloveme
---@param address number offset in memory
---@param length number number of bytes to read
---@return string
local function read_string(address, length)
    local valuebytes = mainmemory.read_bytes_as_array(address, length);
    local valuestring = '';
    for i = 1, length, 1 do
        if valuebytes[i] > 0 then
            valuestring = valuestring..string.char(valuebytes[i])
        end
    end;
    return valuestring;
end;

-- time display by psyouloveme



---Display time and current map
---by psyouloveme
local function draw_clock()
    local hour = mainmemory.readbyte(hour_offset);
    local hour_string = bizstring.pad_start(tostring(hour), 2, 0);
    local minute = mainmemory.readbyte(minute_offset);
    local minute_string = bizstring.pad_start(tostring(mainmemory.readbyte(minute_offset)), 2, 0);
    local day = "aug "..bizstring.pad_start(tostring(mainmemory.readbyte(day_offset)), 2, 0);

    local map_string = bizstring.pad_start(read_string(map_offset, 6), 6, " ");
    local mode_string = bizstring.pad_start(tostring(GAME_MODE), 2, " ");
    local luck = mainmemory.readbyte(luck_offset);

    local time = hour_string .. ":" .. minute_string;
    time = time .. " " .. day;
    time = time .. " " .. map_string;
    gui.drawText(10, 0, time);

    local nextMinute =  mainmemory.readbyte(next_minute_offset);
    if (nextMinute < minute) then
        nextMinute = (nextMinute + 60) - minute;
    else
        nextMinute = nextMinute - minute;
    end

    local next_map_string = bizstring.pad_start(read_string(next_map_offset, 6), 6, " ");
    local next_minute = "+" .. bizstring.pad_start(tostring(nextMinute), 2, 0);
    local nextTimeIncrementText = "  " .. next_minute 
    nextTimeIncrementText = nextTimeIncrementText .. bizstring.pad_start(tostring(next_map_string), 14, " ")
    gui.drawText(10, 11, nextTimeIncrementText);


    local luckAndMode = "Mode:" .. mode_string .. " Luck: " .. tostring(luck);
    gui.drawText(10, 22, luckAndMode)
end;

local function draw_sumo_stats()
    local sumoLevel = mainmemory.readbyte(sumo_level_offset);
    local sumoWins = mainmemory.readbyte(sumo_wins_offset);

    local sumoString = "Sumo Level: " .. tostring(sumoLevel) .. " Wins: " .. tostring(sumoWins);
    gui.drawText(160, 0, sumoString);
end;

---Read a beetle stat structure from memory (12 bytes)
---@param offset number memory offset to read from
---@return table beetle_stat beetle stat table
local function read_beetle_stat(offset)
    local beetle_stat = {
        strength = mainmemory.readbyte(offset);
        unknown0 = mainmemory.readbyte(offset + 1);
        defense0 = mainmemory.readbyte(offset + 2);
        defense1 = mainmemory.readbyte(offset + 3);
        speed = mainmemory.readbyte(offset + 4);
        sicl = mainmemory.read_u16_le(offset + 5);
        unknown1 = mainmemory.readbyte(offset + 7);
        hitpoints = mainmemory.read_s32_le(offset + 8);
    };
    return beetle_stat;
end;

---Draw a beetle stat structure on the screen
---@param beetle_stat table beetle stat table
---@param is_player boolean render on player side or opponent side
local function draw_beetle_stat(beetle_stat, is_player)
    if GAME_MODE ~= 7 then
        return;
    end
    local x;
    local y;
    if is_player then
        gui.drawText(88, 120, 'HP: ' .. bizstring.pad_start(tostring(tostring(beetle_stat.hitpoints)), 4, " "))
        x = 22;
        y = 58;
    else
        gui.drawText(196, 120, 'HP: ' ..  bizstring.pad_start(tostring(tostring(beetle_stat.hitpoints)), 4, " "))
        x = 272;
        y = 70;
    end
   
    local fontsize = 11;
    local y_stride = fontsize - 2;
    local forecolor = nil;
    local backcolor = nil;
    y = y + y_stride;
    gui.drawText(x, y, 'STR :' .. bizstring.pad_start(tostring(beetle_stat.strength), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'UNK0:' .. bizstring.pad_start(tostring(beetle_stat.unknown0), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'DEF0:'  .. bizstring.pad_start(tostring(beetle_stat.defense0), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'DEF1:' .. bizstring.pad_start(tostring(beetle_stat.defense0), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'SPD :' .. bizstring.pad_start(tostring(beetle_stat.speed), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'SICL:' .. bizstring.pad_start(tostring(beetle_stat.speed), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'UNK1:' .. bizstring.pad_start(tostring(beetle_stat.speed), 3, " "), forecolor, backcolor, fontsize);
end;

---Draw beetle stats for the boku and an opponent on screen
local function draw_beetle_stats()
    local beetle_stat;
    local offset = sumo_player_beetle_offset;
    local tmp = mainmemory.readbyte(offset);
    if tmp > 0 then
        beetle_stat = read_beetle_stat(offset);
        draw_beetle_stat(beetle_stat, true)
    end
    offset = sumo_opponent_beetle_offset;
    tmp = mainmemory.readbyte(offset);
    if tmp > 0 then
        beetle_stat = read_beetle_stat(offset);
        draw_beetle_stat(beetle_stat, false)
    end
end;


---Read a bug structure from memory (12 bytes)
---@param offset number memory offset to read from
---@return table bug_struct a bug structure
local function read_bug(offset)
    local bug_stat = {
        type_id      = mainmemory.readbyte(offset);
        size         = mainmemory.readbyte(offset + 1);
        lost_today   = mainmemory.readbyte(offset + 2);
        size_class   = mainmemory.readbyte(offset + 3);
        catch_number = mainmemory.readbyte(offset + 4);
        catch_day    = mainmemory.readbyte(offset + 5);
        wins         = mainmemory.readbyte(offset + 6);
        losses       = mainmemory.readbyte(offset + 7);
        stat         = mainmemory.read_s32_le(offset + 8);
    };
    return bug_stat;
end;

---Draw a header row for a bug table
---@param name string | nil up to four character name to display
local function draw_bug_inline_header(name)
    if name == nil then
        name = ""
    elseif #name > 4 then
        name = bizstring.substring(name, 0, 4)
    end
    local x = 10;
    local fontsize = 11;
    local y = 33;
    local h = "";
    h = h .. bizstring.pad_start(name, 4, " ") .. " ";
    h = h .. " " .. bizstring.pad_start("ID", 2, " ");
    h = h .. " " .. bizstring.pad_start("mm", 3, " ");
    h = h .. " " .. bizstring.pad_start("KO", 2, " ");
    h = h .. " " .. bizstring.pad_start("C", 1, " ");
    h = h .. " " .. bizstring.pad_start("CNo", 3, " ");
    h = h .. " " .. bizstring.pad_start("D", 2, " ");
    h = h .. " " .. bizstring.pad_start("Ws", 3, " ");
    h = h .. " " .. bizstring.pad_start("Ls", 3, " ");
    h = h .. " " .. bizstring.pad_start("Exp?", 5, " ");
    gui.drawText(x, y, h, nil, nil, fontsize);

end;

---Draw a bug structure on the screen
---@param bug table the bug structure to display
---@param index number | nil the index of the bug to dispalay
local function draw_bug_inline(bug, index)
    if index == nil then
        index = 1;
    end
    local x_start = 10;
    local y_start = 33;

    local fontsize = 11;
    local y_stride = fontsize - 2;
    local forecolor = nil;
    if bug.type_id == 99 then
        forecolor = "#b5b5b5";
    end
    local backcolor = nil;

    local x = x_start;
    local y = y_start + (y_stride * index);

    local s = "";
    s = s .. bizstring.pad_start(tostring(index), 3, " ") .. ": ";
    s = s .. " " .. bizstring.pad_start(tostring(bug.type_id), 2, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.size), 3, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.lost_today), 2, " ");
    local size_class = "";
    if bug.size_class == 2 then
        size_class = "B"
    elseif bug.size_class == 1 then
        size_class = "K"
    end
    s = s .. " " .. bizstring.pad_start(tostring(size_class), 1, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.catch_number), 3, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.catch_day), 2, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.wins), 3, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.losses), 3, " ");
    s = s .. " " .. bizstring.pad_start(tostring(bug.stat), 5, " ");

    gui.drawText(x, y, s, forecolor, backcolor, fontsize);
end;

---Draw one or more bug stats in a table on screen
---@param offset number memory offset to read from
---@param count number number of bugs to read
---@param name string name to label table with
local function draw_bug_stats(offset, count, name)
    local o = offset;
    local bug;
    draw_bug_inline_header(name);
    for i = 1, count, 1 do
        bug = read_bug(o);
        draw_bug_inline(bug, i);
        o = o + 12;
    end
end;

local bug_stat_page = 0;
local bug_stat_pages = 7;
local bug_page_plus_counter = 0;
local bug_page_minus_counter = 0;

---Draw bug inventories to the screen
local function draw_bug_inventories()
    local t = joypad.get();
    if t["P1 R2"] == true then
        if t["P1 D-Pad Right"] == true then
            bug_page_plus_counter = bug_page_plus_counter + 1;
            bug_page_minus_counter = 0;
        elseif t["P1 D-Pad Left"] == true then
            bug_page_minus_counter = bug_page_minus_counter + 1;
            bug_page_plus_counter = 0;
        else
            bug_page_minus_counter = 0;
            bug_page_plus_counter = 0;
        end
    else
        bug_page_minus_counter = 0;
        bug_page_plus_counter = 0;
    end

    if bug_page_minus_counter == 15 then
        if bug_stat_page - 1 < 0 then
            bug_stat_page = bug_stat_pages - 1;
        else
            bug_stat_page = bug_stat_page - 1;
        end
        bug_page_minus_counter = 0;
    end

    if bug_page_plus_counter == 15 then
        if bug_stat_page + 1 == bug_stat_pages then
            bug_stat_page = 0;
        else
            bug_stat_page = bug_stat_page + 1;
        end
        bug_page_plus_counter = 0;
    end

    if bug_stat_page == 0 then
        draw_bug_stats(fatBugArray, 20, "Fat");
    elseif bug_stat_page == 1 then
        draw_bug_stats(glassesBugArray, 20, "Glasses");
    elseif bug_stat_page == 2 then
        draw_bug_stats(gutsBugArray, 20, "Guts");
    elseif bug_stat_page == 4 then
        draw_bug_stats(bugArray, 15, "Tra1")
    elseif bug_stat_page == 5 then
        draw_bug_stats(bugArray + (15 * bugStructSize), 15, "Tra2")
    -- elseif bug_stat_page == 5 then
    --     draw_bug_stats(bigBugStruct, 20, "BBS1")
    -- elseif bug_stat_page == 6 then
    --     draw_bug_stats(bigBugStruct + (20 * bugStructSize), 20, "BBS2")
    -- elseif bug_stat_page == 7 then
    --     draw_bug_stats(bigBugStruct + (40 * bugStructSize), 20, "BBS3")
    -- elseif bug_stat_page == 8 then
    --     draw_bug_stats(bigBugStruct + (60 * bugStructSize), 20, "BBS4")
    -- elseif bug_stat_page == 9 then
    --     draw_bug_stats(bigBugStruct + (80 * bugStructSize), 20, "BBS5")
    -- elseif bug_stat_page == 10 then
    --     draw_bug_stats(bigBugStruct + (100 * bugStructSize), 20, "BBS6")
    -- elseif bug_stat_page == 11 then
    --     draw_bug_stats(bigBugStruct + (120 * bugStructSize), 20, "BBS7")
    -- elseif bug_stat_page == 12 then
    --     draw_bug_stats(bigBugStruct + (140 * bugStructSize), 10, "BBS8")
    elseif bug_stat_page == 6 then
        draw_bug_inline_header("Misc");
        local bug = read_bug(singleBug);
        draw_bug_inline(bug, 1);
        bug = read_bug(singleBugTwo);
        draw_bug_inline(bug, 2);
        bug = read_bug(singleBugThree);
        draw_bug_inline(bug, 3);
        bug = read_bug(singleBugFour);
        draw_bug_inline(bug, 4);
        bug = read_bug(singleBugFive);
        draw_bug_inline(bug, 5);
    elseif bug_stat_page == 3 then
        draw_bug_stats(bokuBugArray, 10, "Boku")
    end
    -- read guts bugs
end;








---Draw the last CD position to the screen
local function draw_cdpos()
    local cdminute = mainmemory.readbyte(cdpos_last_minute_offset);
    local cdsecond = mainmemory.readbyte(cdpos_last_second_offset);
    local cdsector = mainmemory.readbyte(cdpos_last_sector_offset);

    
    -- local cdminute = 11;
    -- local cdsecond = 46;
    -- local cdsector = 60;

    -- local cdpos = cdIntToPos(0x3d80);
    local cdint = cdPosToInt(cdminute, cdsecond, cdsector);
    local cdstring = bizstring.pad_start(tostring(cdminute), 3, 0) .. ':' .. bizstring.pad_start(tostring(cdsecond), 2, 0) .. ':' .. bizstring.pad_start(tostring(cdsector), 3, 0) .. '-' .. tostring(cdint);
    -- local cdstring = bizstring.pad_start(tostring(cdpos.minute), 3, 0) .. ':' .. bizstring.pad_start(tostring(cdpos.second), 2, 0) .. ':' .. bizstring.pad_start(tostring(cdpos.sector), 3, 0) .. '-' .. tostring(0x3d80);
    -- local cdstring = bizstring.pad_start(tostring(cdpos.minute), 3, 0) .. ':' .. bizstring.pad_start(tostring(cdpos.second), 2, 0) .. ':' .. bizstring.pad_start(tostring(cdpos.sector), 3, 0) .. '-' .. tostring(cdint);
    gui.drawText(10, 33, cdstring);
end;

---Draw achived story flags to the screen
local function draw_story_flags()
    -- storypoints display by Ted and psyouloveme
    --  1 ????
    --  2 flowers
    --  3 corn
    --  4 Moe 1
    --  5 Moe 2
    --  6 Shirabe 1
    --  7 Shirabe 2
    --  8 fish
    --  9 shortcut
    -- 10 wolf
    -- 11 ????
    -- 12 firelifes
    -- 13 mountain
    -- 14 snakeskin
    -- 15 shirabe 3
    -- 16 rain

    local pointsraw = mainmemory.readbyte(story_point_offset);
    local points = 0;
    local point_to_draw = 0;
    local point_name = "";
    local point_ypos = 33;
    for i = 0, 15 do
        if ((pointsraw & (1 << i)) ~= 0) then
            point_to_draw = i + 1;
            point_ypos = 30 + (points * 10);
            if point_to_draw == 1 then
                point_name = " - what is this"
            elseif point_to_draw == 2 then
                point_name = " - morning glories"
            elseif point_to_draw == 3 then
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
                point_name = " - jumbo";
            elseif point_to_draw == 9 then
                point_name = " - secret shortcut";
            elseif point_to_draw == 10 then
                point_name = " - wolf";
            elseif point_to_draw == 11 then
                point_name = " - what is this";
            elseif point_to_draw == 12 then
                point_name = " - fireflies";
            elseif point_to_draw == 13 then
                point_name = " - mountain top";
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
    if (points >= 0) then
        local points_text_bin = bizstring.pad_start(bizstring.binary(pointsraw), 16, 0);
        local points_text_hex = bizstring.pad_start(bizstring.hex(pointsraw), 4, 0).."h";
        gui.drawText(160, 0, "Major Event Flags");
        gui.drawText(160, 10, points_text_bin);
        gui.drawText(160, 20, points_text_hex);
    end
end;

---Draw the status of the beehive to the screen
local function draw_beehive_status()
    local hit_hive_today = mainmemory.readbyte(beehive_hit_today_offset);
    local total_hive_hits = mainmemory.readbyte(beehive_total_hit_offset);

    local hit_count_string;
    if total_hive_hits == 0 then
        hit_count_string = "hive not hit";
    elseif total_hive_hits > 0 and total_hive_hits < 4 then
        hit_count_string = "hive hits "..tostring(total_hive_hits).."/4";
    elseif total_hive_hits == 4 then
        hit_count_string = "hive down";
    end

    local hit_today_string;
    if hit_hive_today == 1 and total_hive_hits == 4 then
        hit_today_string = "today";
    elseif hit_hive_today == 1 and total_hive_hits ~= 4 then
        hit_today_string = "hit today";
    elseif hit_hive_today ~= 1 and total_hive_hits > 0 and total_hive_hits < 4 then
        hit_today_string = "not today";
    else
        hit_today_string = nil;
    end

    local status_string = hit_count_string;
    if hit_today_string ~= nil then
        status_string = status_string .. " " .. hit_today_string;
    end

    gui.drawText(160, 30, status_string);
end

---Draw the status of the tree to the screen
local function draw_tree_status()
    local treehits = mainmemory.readbyte(tree_hits_offset);
    -- local treehits = mainmemory.readbyte(0x035E91);
    -- local hivehits = mainmemory.readbyte(0x035EE3);
    -- local hit_string = "hive hits: "..tostring(total_hive_hits).."/4";
    if treehits > 0 and treehits < 5 then
        gui.drawText(160, 40, "tree hits: "..tostring(treehits).. "/5");
    elseif treehits > 0 and treehits > 5 then
        gui.drawText(160, 40, "tree down.");
    end
end

---Draw the status of the flowers to the screen
local function draw_flower_status()
    gui.drawText(160, 50, "Flowers:");

    local flowerswatered = mainmemory.readbyte(water_level_offset);
    gui.drawText(170, 60, "water level?: "..tostring(flowerswatered));

    local fw = mainmemory.readbyte(blooms_offset);
    gui.drawText(170, 70, "blooms?: "..tostring(fw));

    local hydrationLevel = mainmemory.readbyte(watered_today_offset);
    gui.drawText(170, 80, "watered today?: "..tostring(hydrationLevel));
end

local holdcount = 0
local current_page = 1;
local page_count = 3;
local pages = {};
pages[0] = {};
pages[1] = {};
pages[2] = {};
table.insert(pages[0], draw_clock);
table.insert(pages[0], draw_story_flags);
table.insert(pages[0], draw_beehive_status);
table.insert(pages[0], draw_tree_status);
table.insert(pages[0], draw_flower_status);
table.insert(pages[1], draw_clock);
table.insert(pages[1], draw_cdpos);
table.insert(pages[1], draw_beetle_stats);
table.insert(pages[1], draw_sumo_stats);
table.insert(pages[2], draw_clock);
table.insert(pages[2], draw_bug_inventories);
table.insert(pages[2], draw_sumo_stats);

---Main loop
while true do
    gui.defaultBackground("#0bffffff")
    GAME_MODE = mainmemory.readbyte(mode_offset)
    local t = joypad.get();
    if t["P1 R1"] == true then
        holdcount = holdcount + 1
    else
        holdcount = 0
    end
    if holdcount == 60 then
        holdcount = 0
        if current_page + 1 == page_count then
            current_page = 0;
        else
            current_page = current_page + 1;
        end
    end
    for index, value in ipairs(pages[current_page]) do
        value();
    end
    emu.frameadvance();
end

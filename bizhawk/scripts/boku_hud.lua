---do this dumb workaround to get typing for the global
_G.mainmemory = _G.mainmemory
_G.bizstring = _G.bizstring
_G.emu = _G.emu
_G.joypad = _G.joypad
_G.gui = _G.gui
_G.client = _G.client

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

local on_screen_bug_id = 0x028074;
local on_screen_bug_struct_size = 0x58;
local on_screen_bug_struct_count = 0xE;

local function bug_id_to_string(id)
    if id == 0 then return "Asian Swallowtail" end;
    if id == 1 then return "Old World Swallowtail" end;
    if id == 2 then return "Long Tail Spangle" end;
    if id == 3 then return "Chinese Peacock Swallowtail" end;
    if id == 4 then return "Musk swallowtail butterfly" end;
    if id == 5 then return "Common bluebottle" end;
    if id == 6 then return "Mikado Swallowtail" end;
    if id == 7 then return "Small White" end;
    if id == 8 then return "Eastern Pale Clouded Yellow" end;
    if id == 9 then return "Indian Red Admiral" end;
    if id == 10 then return "Comma" end;
    if id == 11 then return "Blue Admiral" end;
    if id == 12 then return "European Peacock" end;
    if id == 13 then return "Great Purple Emperor" end;
    if id == 14 then return "Poplar Admiral" end;
    if id == 15 then return "Tailless Bushblue" end;
    if id == 16 then return "Green hairstreak" end;
    if id == 17 then return "Pale Grass Blue" end;
    if id == 18 then return "Swallow Short-tailed Blue" end;
    if id == 19 then return "Chestnut Tiger" end;
    if id == 20 then return "Chinese Bushbrown" end;
    if id == 21 then return "European Beak" end;
    if id == 22 then return "Indian Awlking" end;
    if id == 23 then return "Miyama Stag Beetle ♂" end;
    if id == 24 then return "Japanese Great Stag Beetle ♂" end;
    if id == 25 then return "Titan Stag Beetle" end;
    if id == 26 then return "Little Stag Beetle" end;
    if id == 27 then return "Saw Stag Beetle ♂" end;
    if id == 28 then return "Asian Red-footed Stag Beetle" end;
    if id == 29 then return "Oni Stag Beetle" end;
    if id == 30 then return "Rhinoceros Beetle ♂" end;
    if id == 31 then return "Heike Firefly" end;
    if id == 32 then return "Damselfly" end;
    if id == 33 then return "Japanese Relict Dragonfly" end;
    if id == 34 then return "??? Dragonfly" end;
    if id == 35 then return "Jumbo Dragonfly" end;
    if id == 36 then return "Lesser Emperor" end;
    if id == 37 then return "White-tailed Skimmer" end;
    if id == 38 then return "Summer Darter dragonfly" end;
    if id == 39 then return "Mayutate akane dragonfly" end;
    if id == 40 then return "Butterfly Dragonfly" end;
    if id == 41 then return "Migratory Locust" end;
    if id == 42 then return "Japanese Bush Cricket" end;
    if id == 43 then return "Kusakiri Bush Cricket" end;
    if id == 44 then return "Forest Bush Cricket" end;
    if id == 45 then return "Japanese Katydid" end;
    if id == 46 then return "Emma Field Cricket" end;
    if id == 47 then return "Skylark Sword-tailed Cricket" end;
    if id == 48 then return "Bell Cricket" end;
    if id == 49 then return "Japanese Pine Cricket" end;
    if id == 50 then return "Kempfer Cicada" end;
    if id == 51 then return "Large Brown Cicada" end;
    if id == 52 then return "Ezo Cicada" end;
    if id == 53 then return "Evening Cicada" end;
    if id == 54 then return "Robust Cicada" end;
    if id == 55 then return "Last Summer Cicada" end;
    if id == 56 then return "Miyama Stag Beetle ♀" end;
    if id == 57 then return "Japanese Great Stag Beetle ♀" end;
    if id == 58 then return "Saw Stag Beetle ♀" end;
    if id == 59 then return "Rhinoceros Beetle ♀" end;
    return bizstring.hex(id);
end


---Convert CD Pos to Int
---@param minute number
---@param second number
---@param sector number
---@return number
local function cdPosToInt(minute, second, sector)
    return (((minute >> 4) * 10 + (minute & 15)) * 60 + (second >> 4) * 10 + (second & 15)) * 75 + (sector >> 4) * 10 + (sector & 15) + -150;
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


---Display time and current map
---by psyouloveme
local function draw_clock()
    local hour = mainmemory.readbyte(hour_offset);
    local hour_string = bizstring.pad_start(tostring(hour), 2, 0);
    local minute = mainmemory.readbyte(minute_offset);
    local minute_string = bizstring.pad_start(tostring(mainmemory.readbyte(minute_offset)), 2, 0);
    local day = "aug "..bizstring.pad_start(tostring(mainmemory.readbyte(day_offset)), 2, 0);

    local raw_map_string = read_string(map_offset, 6);
    local map_string = bizstring.pad_start(raw_map_string, 6, " ");

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

    local next_map_raw = read_string(next_map_offset, 6);
    local next_map_string = bizstring.pad_start(next_map_raw, 6, " ");
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
        if t["P1 Right"] == true then
            bug_page_plus_counter = bug_page_plus_counter + 1;
            bug_page_minus_counter = 0;
        elseif t["P1 Left"] == true then
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

    if bug_page_minus_counter == 20 then
        if bug_stat_page - 1 < 0 then
            bug_stat_page = bug_stat_pages - 1;
        else
            bug_stat_page = bug_stat_page - 1;
        end
        bug_page_minus_counter = 0;
    end

    if bug_page_plus_counter == 20 then
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
    local cdint = cdPosToInt(cdminute, cdsecond, cdsector);
    local cdstring = bizstring.pad_start(tostring(cdminute), 3, 0) .. ':' .. bizstring.pad_start(tostring(cdsecond), 2, 0) .. ':' .. bizstring.pad_start(tostring(cdsector), 3, 0) .. '-' .. tostring(cdint);
    gui.drawText(10, 33, cdstring);
end;

---Draw achived story flags to the screen
local function draw_story_flags()
    -- storypoints display by Ted and psyouloveme
    -- -  1 ???? shirabe 3 or kites
    -- -  2 Make the morning glories bloom for 9 days (awarded after credits )
    -- -  3 Help aunt and uncle pick corn
    -- -  4 Help Moe gather flowers to press
    -- -  5 Give Moe the book from the waterfall cave
    -- -  6 Spend time with Shirabe on the 4th
    -- -  7 Spend time at Cape Kaze with Shirabe on the 14th
    -- -  8 Catch the large trout, Jumbo
    -- -  9 Win the sumo tournament and enter the secret area 
    -- - 10 Get a photo of a Japanese wolf
    -- - 11 ????                                         shirabe 3 or kites
    -- - 12 See the fireflies on the 5th
    -- - 13 Climb to the top of the mountain
    -- - 14 Obtain a snake skin
    -- - 15 shirabe 3
    -- - 16 See the rain at the overpass on the 26th or 27th
 
    local pointsraw = mainmemory.readbyte(story_point_offset);
    local points = 0;
    local point_to_draw = 0;
    local point_name = "";
    local point_ypos = 33;
    for i = 0, 17 do
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
                point_name = " - moe flowers";
            elseif point_to_draw == 5 then
                point_name = " - moe book";
            elseif point_to_draw == 6 then
                point_name = " - shirabe 4th";
            elseif point_to_draw == 7 then
                point_name = " - shirabe 14th";
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

local function draw_screen_bugs()
    local bug_id = mainmemory.read_u16_le(on_screen_bug_id);
    local bug_count = mainmemory.read_u16_le(0x02806c);
    local fontsize = 11;
    local x = 10;
    local y = 33;
    local y_stride = fontsize - 1;
    gui.drawText(x, y, "Bug count: " .. tostring(bug_count))
    y = y + y_stride;
    for current_index = 0, bug_count-1, 1 do
        bug_id = mainmemory.read_u16_le(on_screen_bug_id + (current_index * on_screen_bug_struct_size))
        gui.drawText(x, y, bizstring.pad_start(tostring(current_index), 2, " ") .. ": " .. bizstring.pad_start(bizstring.hex(bug_id), 2, " ") .. " " .. bug_id_to_string(bug_id));
        y = y + y_stride;
    end
end;

local holdcount = 0
local current_page = 1;
local page_count = 4;
local pages = {};
pages[0] = {};
pages[1] = {};
pages[2] = {};
pages[3] = {};
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
table.insert(pages[3], draw_clock);
table.insert(pages[3], draw_screen_bugs);

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

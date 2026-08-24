-- Boku no Natsuyasumi Hud v2.0.1
-- by psyouloveme with help from Tedder
-- Latest version is here https://github.com/psyouloveme/boku1-reversing/blob/master/bizhawk/scripts/boku_hud.lua

print("Boku no Natsuyasumi Hud v2.0.1\n")
print("Press Select to open the menu.")
print("Press R1 to change pages.\n")
print("This script expects the Octoshock PSX core, it might not work correctly using others.")
print("If you need to change your PSX core go to:")
print("  Config -> Preferred Cores -> For Consoles -> PSX -> Ocotoshock")
print("Then close the game and open it again.")
print("Get the latest version here: https://github.com/psyouloveme/boku1-reversing/blob/master/bizhawk/scripts/boku_hud.lua")

---do this dumb workaround to get typing for the global
_G.mainmemory = _G.mainmemory
_G.bizstring = _G.bizstring
_G.emu = _G.emu
_G.joypad = _G.joypad
_G.gui = _G.gui
_G.client = _G.client

-- #region Constants
local GameModeOffset = 0x237e0;
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
local DayCurrentOffset = 0x028fb0;
local HourCurrentOffset = 0x028FA1;
local LuckOffset = 0x3dd1d;
local MinuteCurrentOffset = 0x028FA2;
local MinuteNextOffset = 0x028FB2;
local MapCurrentOffset = 0x26c00;
local MapNextOffset = 0x26c08;
local FrameCountOffset = 0x028850;
-- sumo basic stats
local SumoLevelOffset = 0x3d278;
local SumoWinsOffset = 0x3d279;
-- sumo match info
local sumo_player_beetle_offset = 0x8f028;
local sumo_opponent_beetle_offset = 0x8f098;
-- last CD POS
local cdpos_last_minute_offset = 0x025A40;
local cdpos_last_second_offset = 0x025A41;
local cdpos_last_sector_offset = 0x025A42;
-- story point bitfield
local StoryEventsOffset = 0x035f35;
-- beehive hits
local NestHitsTodayOffset = 0x035EE2;
local NestTotalHitsOffset = 0x035EE3;
-- tree hit status
local TreeHitsOffset = 0x035E91;
-- flowers
local FlowerWaterLevelOffset = 0x035E92;
local FlowerBloomsOffset = 0x035E93;
local FlowersWateredTodayOffset = 0x035E4E;
-- bugs on screen
local on_screen_bug_count = 0x02806c;
local on_screen_bug_id =     0x028074;
local on_screen_bug_caught = 0x0280A4;
local on_screen_bug_size = 0x0280A5;
local on_screen_bug_struct_size = 0x58; 
-- pausing
-- 0 when not paused
-- 1 when paused
local PauseStateOffset = 0x0246b8;
-- 2 when pause screen is closed.
-- 1 when pause screen is opening or closing.
-- 0 when pause screen is fully open.
local PauseAnimationStateOffset = 0x0366f8;
-- pause animation timer.
-- starts at 0 when closed.
-- counts up to 15 when opened.
-- stays at 15 while open.
-- counts down to 0 when closed.
local PauseAnimationTimerOffset = 0x0366f9;

-- joypad button states
local ButtonState = {
    -- previous frame button not pressed
    -- this frame button not pressed
    Neutral = 0;
    -- previous frame button not pressed
    -- this frame button pressed
    Pressed = 1;
    -- previous frame button pressed
    -- this frame button pressed
    Held = 2;
    -- previous frame button pressed
    -- this frame button not pressed
    Released = 3;
}

-- joypad control names for Octoshock
local Button = {
    P1Up = "P1 Up";
    P1Down = "P1 Down";
    P1Left = "P1 Left";
    P1Right = "P1 Right";
    P1Start = "P1 Start";
    P1Select = "P1 Select";
    P1Cross = "P1 Cross";
    P1Cicle = "P1 Circle";
    P1Triangle = "P1 Triangle";
    P1Sqare = "P1 Square";
    P1L1 = "P1 L1";
    P1L2 = "P1 L2";
    P1R1 = "P1 R1";
    P1R2 = "P1 R2";
};

local Mode = {
    StartUp = 0,
    MenuOpening = 3,
    MenuOpen = 4,
    Game = 5,
    Sumo = 7
};
-- #endregion

-- #region Globals

--- game mode
--- 3 = menu opening.
--- 4 = in menu.
--- 5 = main game mode.
--- 7 = sumo.
local GameMode = 0;
local GameModePrevious = GameMode;

--- date/time
local Day = 0;
local Hour = 0;
local Minute = 0;
local MinuteNext = 0;

-- maps
local Screen = nil;
local ScreenNext = nil;

-- frame count
local FrameCount = 0;

--- joypad
local JoypadRaw = nil;
local JoypadRawPrevious = nil;
local JoypadState = {};
local JoypadHoldStateCount = {};

--- gui
local Width = 0;
local Height = 0;

-- meta
local HudMenuOpen = false;
local HudPage = 1;
local HudPagePrevious = -1;
local HudPageDrawFns = {};
local HudPageInitFns = {};
local HudPageExitFns = {};
local HudPageNames = {};

local TimeFreeze = false;
local TimeFreezeValue = nil;

-- Global for timer reset
local ResetOnScreenChange = false;

-- #endregion


local function BugIdToString(id)
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
local function CdPosToInt(minute, second, sector)
    return (((minute >> 4) * 10 + (minute & 15)) * 60 + (second >> 4) * 10 + (second & 15)) * 75 + (sector >> 4) * 10 + (sector & 15) + -150;
end

---Read a string from memory
---by psyouloveme
---@param address number offset in memory
---@param length number number of bytes to read
---@return string
local function ReadString(address, length)
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
local function DrawClock()
    local hour_string = bizstring.pad_start(tostring(Hour), 2, 0);
    local minute_string = bizstring.pad_start(tostring(Minute), 2, 0);
    local day = "aug "..bizstring.pad_start(Day, 2, 0);
    local map_string = bizstring.pad_end(Screen, 6, " ");

    local mode_string = bizstring.pad_start(tostring(GameMode), 2, " ");
    local luck = mainmemory.readbyte(LuckOffset);

    local time = hour_string .. ":" .. minute_string;
    time = time .. " " .. day;
    time = time .. " " .. map_string;
    if TimeFreeze then
        gui.drawText(10, 0, time, "#FF0ca6f9");
    else
        gui.drawText(10, 0, time);
    end
    

    local minute = Minute;
    local nextMinute = MinuteNext;
    if (nextMinute < minute) then
        nextMinute = (nextMinute + 60) - minute;
    else
        nextMinute = nextMinute - minute;
    end

    local next_map_string = bizstring.pad_end(ScreenNext, 6, " ");
    local next_minute = "+" .. bizstring.pad_start(tostring(nextMinute), 2, 0);
    local nextTimeIncrementText = "  " .. next_minute 
    nextTimeIncrementText = nextTimeIncrementText .. bizstring.pad_start(tostring(next_map_string), 14, " ")
    gui.drawText(10, 11, nextTimeIncrementText);

    local luckAndMode = "Mode:" .. mode_string .. " Luck: " .. tostring(luck);
    gui.drawText(10, 22, luckAndMode)
end;

local function DrawSumoStats()
    local sumoLevel = mainmemory.readbyte(SumoLevelOffset);
    local sumoWins = mainmemory.readbyte(SumoWinsOffset);

    local sumoString = "Sumo Level: " .. tostring(sumoLevel) .. " Wins: " .. tostring(sumoWins);
    gui.drawText(160, 0, sumoString);
end;

---Read a beetle stat structure from memory (12 bytes)
---@param offset number memory offset to read from
---@return table beetle_stat beetle stat table
local function ReadFighterStats(offset)
    local beetle_stat = {
        strength = mainmemory.readbyte(offset);
        unknown0 = mainmemory.readbyte(offset + 1);
        defense0 = mainmemory.readbyte(offset + 2);
        defense1 = mainmemory.readbyte(offset + 3);
        speed = mainmemory.readbyte(offset + 4);
        sicl = mainmemory.read_u16_le(offset + 5);
        unknown1 = mainmemory.readbyte(offset + 7);
        hitpoints = mainmemory.read_s32_le(offset + 8);
        taps = mainmemory.readbyte(offset + 0x3e);
    };
    return beetle_stat;
end;

---Draw a beetle stat structure on the screen
---@param beetle_stat table beetle stat table
---@param is_player boolean render on player side or opponent side
local function DrawFighterStats(beetle_stat, is_player)
    if GameMode ~= Mode.Sumo then
        gui.drawText(160, 11, "Waiting for Sumo mode.")
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
    gui.drawText(x, y, 'Tap :' .. bizstring.pad_start(tostring(beetle_stat.taps), 3, " "), forecolor, backcolor, fontsize);
    y = y + y_stride;
    gui.drawText(x, y, 'STR :' .. bizstring.pad_start(tostring(beetle_stat.strength), 3, " "), forecolor, backcolor, fontsize);
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
local function DrawFightersStats()
    if GameMode ~= Mode.Sumo then
        gui.drawText(160, 11, "Waiting for Sumo mode.")
        return;
    end
    local beetle_stat;
    local offset = sumo_player_beetle_offset;
    local tmp = mainmemory.readbyte(offset);
    if tmp > 0 then
        beetle_stat = ReadFighterStats(offset);
        DrawFighterStats(beetle_stat, true)
    end
    offset = sumo_opponent_beetle_offset;
    tmp = mainmemory.readbyte(offset);
    if tmp > 0 then
        beetle_stat = ReadFighterStats(offset);
        DrawFighterStats(beetle_stat, false)
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

---Draw bug inventories to the screen
local function DrawBugInventories()
    if JoypadState[Button.P1R2] == ButtonState.Held then
        if JoypadState[Button.P1Right] == ButtonState.Pressed then
            if bug_stat_page + 1 == bug_stat_pages then
                bug_stat_page = 0;
            else
                bug_stat_page = bug_stat_page + 1;
            end;
        elseif JoypadState[Button.P1Left] == ButtonState.Pressed then
            if bug_stat_page - 1 < 0 then
                bug_stat_page = bug_stat_pages - 1;
            else
                bug_stat_page = bug_stat_page - 1;
            end;
        end;
    end;

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
local function DrawCdPos()
    local cdminute = mainmemory.readbyte(cdpos_last_minute_offset);
    local cdsecond = mainmemory.readbyte(cdpos_last_second_offset);
    local cdsector = mainmemory.readbyte(cdpos_last_sector_offset);
    local cdint = CdPosToInt(cdminute, cdsecond, cdsector);
    local cdstring = bizstring.pad_start(tostring(cdminute), 3, 0) .. ':' .. bizstring.pad_start(tostring(cdsecond), 2, 0) .. ':' .. bizstring.pad_start(tostring(cdsector), 3, 0) .. '-' .. tostring(cdint);
    gui.drawText(10, 33, cdstring);
end;

---Draw achived story flags to the screen
local function DrawStoryEventFlags()
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
 
    local pointsraw = mainmemory.readbyte(StoryEventsOffset);
    local points = 0;
    local point_to_draw = 0;
    local point_name = "";
    local point_ypos = 33;
    for i = 0, 17 do
        if ((pointsraw & (1 << i)) ~= 0) then
            point_to_draw = i + 1;
            point_ypos = 33 + (points * 11);
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
local function DrawBeehiveStatus()
    local hit_hive_today = mainmemory.readbyte(NestHitsTodayOffset);
    local total_hive_hits = mainmemory.readbyte(NestTotalHitsOffset);

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
local function DrawTreeChopStatus()
    local treehits = mainmemory.readbyte(TreeHitsOffset);
    if treehits > 0 and treehits < 5 then
        gui.drawText(160, 40, "tree hits: "..tostring(treehits).. "/5");
    elseif treehits > 0 and treehits > 5 then
        gui.drawText(160, 40, "tree down.");
    end
end

---Draw the status of the flowers to the screen
local function DrawFlowersStatus()
    gui.drawText(160, 50, "Flowers:");

    local flowerswatered = mainmemory.readbyte(FlowerWaterLevelOffset);
    gui.drawText(170, 60, "water level?: "..tostring(flowerswatered));

    local fw = mainmemory.readbyte(FlowerBloomsOffset);
    gui.drawText(170, 70, "blooms?: "..tostring(fw));

    local hydrationLevel = mainmemory.readbyte(FlowersWateredTodayOffset);
    gui.drawText(170, 80, "watered today?: "..tostring(hydrationLevel));
end

local function DrawOnScreenBugs()
    local bug_count = mainmemory.read_u16_le(on_screen_bug_count);
    local fontsize = 11;
    local x = 10;
    local y = 33;
    local y_stride = fontsize + 1;
    gui.drawText(x, y, "Bug count: " .. tostring(bug_count))
    y = y + y_stride;
    for current_index = 0, bug_count-1, 1 do
        local bug_id = mainmemory.read_u16_le(on_screen_bug_id + (current_index * on_screen_bug_struct_size))
        local bug_size = mainmemory.readbyte(on_screen_bug_size + (current_index * on_screen_bug_struct_size))
        local bug_caught = mainmemory.readbyte(on_screen_bug_caught + (current_index * on_screen_bug_struct_size))
        local bug_txt = BugIdToString(bug_id) .. " " .. tostring(bug_size) .. "mm"
        if bug_caught > 0 then
            bug_txt = "x " .. bug_txt
        else
            bug_txt = "  " .. bug_txt
        end
        gui.drawText(x, y, bug_txt)
        y = y + y_stride;
    end;
end;

local last_screen = nil;
local last_time_lrt = 0;
local last_time_rta = 0;
local last_frame_count = 0;
local frames_since_last_update = 0;
local time_on_screen_lrt = 0;
local time_on_screen_rta = 0;
local pause_frames_lrt = 0;
local last_pause_frames_lrt = 0;
local total_time_rta = 0;
local total_time_lrt = 0;
local total_pause_frames = 0;

local function InitTimer()
    frames_since_last_update = 0;
    last_frame_count = 0;
    last_pause_frames_lrt = 0;
    last_screen = nil;
    last_time_lrt = 0;
    last_time_rta = 0;
    pause_frames_lrt = 0;
    time_on_screen_lrt = 0;
    time_on_screen_rta = 0;
    total_pause_frames = 0;
    total_time_lrt = 0;
    total_time_rta = 0;
    total_time_lrt = 0;
    total_pause_frames = 0;
    ResetOnScreenChange = false;
end;

local function DrawTimer()
    if JoypadState[Button.P1R2] == ButtonState.Pressed then
        ResetOnScreenChange = not ResetOnScreenChange;
    end;
    if ResetOnScreenChange then
        gui.drawText(160, 0, "Resetting next screen.")
        gui.drawText(160, 11, "R2 to Cancel.")
    else
        gui.drawText(160, 0, "R2 reset next screen.")
    end
    local frameCountChanged = false;
    if last_frame_count ~= FrameCount then frameCountChanged = true end;

    total_time_rta = total_time_rta + .1/6;
    if GameMode ~= Mode.Game then
        if last_time_lrt ~= nil then
            last_time_lrt = time_on_screen_lrt;
            last_time_rta = time_on_screen_rta;
            gui.drawText(10, 33, string.format("Total LRT: %.3f (%.3f)", total_time_lrt, total_pause_frames))
            gui.drawText(10, 44, string.format("Total RTA: %.3f", total_time_rta))
            gui.drawText(10, 66, string.format("Last LRT: %.3f (%.3f)", last_time_lrt, last_pause_frames_lrt))
            gui.drawText(10, 77, string.format("Last RTA: %.3f", last_time_rta))
        end;
        return;
    end;

    time_on_screen_rta = time_on_screen_rta + .1/6;

    -- if MAP_NEXT ~= "REMAP" then
    if ScreenNext ~= "REMAP" then
        if frameCountChanged then
            frames_since_last_update = 0;
        else
            frames_since_last_update = frames_since_last_update + 1;
        end;

        if frames_since_last_update < 2 then
            time_on_screen_lrt = time_on_screen_lrt + .1/6;
            total_time_lrt = total_time_lrt + .1/6;
        else
            pause_frames_lrt = pause_frames_lrt + .1/6;
            total_pause_frames = total_pause_frames + .1/6;
        end
    else
        pause_frames_lrt = pause_frames_lrt + .1/6;
        total_pause_frames = total_pause_frames + .1/6;
    end

    if last_screen ~= Screen then
        if ResetOnScreenChange == true then
            InitTimer();
        else
            last_time_lrt = time_on_screen_lrt;
            last_time_rta = time_on_screen_rta;
            last_pause_frames_lrt = pause_frames_lrt;
            time_on_screen_rta = 0;
            time_on_screen_lrt = 0;
            pause_frames_lrt = 0;
        end
    end

    gui.drawText(10, 33, string.format("Total LRT: %.3f (%.3f)", total_time_lrt, total_pause_frames))
    gui.drawText(10, 44, string.format("Total RTA: %.3f", total_time_rta))
    gui.drawText(10, 66, string.format("Last LRT: %.3f (%.3f)", last_time_lrt, last_pause_frames_lrt))
    gui.drawText(10, 77, string.format("Last RTA: %.3f", last_time_rta))
    gui.drawText(10, 99, string.format("LRT: %.3f (%.3f)", time_on_screen_lrt, pause_frames_lrt))
    gui.drawText(10, 110, string.format("RTA: %.3f", time_on_screen_rta))

    last_screen = Screen
    last_frame_count = FrameCount
end;

local function AddPage(name, initFn, exitFn, ...)
    table.insert(HudPageNames, name);
    local drawFnTable = {};
    local g = table.pack(...);
    for i = 1, g.n do
        table.insert(drawFnTable, g[i])
    end;
    table.insert(HudPageDrawFns, drawFnTable);
    table.insert(HudPageInitFns, initFn ~= nil and initFn or function() end);
    table.insert(HudPageExitFns, exitFn ~= nil and exitFn or function() end);
end;

local function UpdateJoypadState()
    local curr = joypad.get()
    if curr == nil then return end;
    if JoypadRaw == nil then
        JoypadRawPrevious = curr;
    else
        JoypadRawPrevious = JoypadRaw;
    end;
    JoypadRaw = curr;
    JoypadState = {};
    JoypadHoldStateCount = {};
    for idx, value in pairs(Button) do
        local p = JoypadRawPrevious[value];
        local c = JoypadRaw[value];
        if JoypadHoldStateCount[value] == nil then JoypadHoldStateCount[value] = 0; end;
        if not p and not c then
            JoypadState[value] = ButtonState.Neutral;
            JoypadHoldStateCount[value] = 0;
        elseif not p and c then
            JoypadState[value] = ButtonState.Pressed;
            JoypadHoldStateCount[value] = 0;
        elseif p and c then
            JoypadState[value] = ButtonState.Held;
            JoypadHoldStateCount[value] = JoypadHoldStateCount[value] + 1;
        else
            JoypadState[value] = ButtonState.Released;
            JoypadHoldStateCount[value] = 0;
        end
    end;
end;

local function UpdateGlobals()  
    if HudMenuOpen ~= true then
        HudPagePrevious = HudPage;
    end;
    GameModePrevious = GameMode;
    UpdateJoypadState();
    GameMode = mainmemory.readbyte(GameModeOffset);
    Screen =  ReadString(MapCurrentOffset, 6);
    ScreenNext = ReadString(MapNextOffset, 6);
    Day = mainmemory.readbyte(DayCurrentOffset);
    Hour = mainmemory.readbyte(HourCurrentOffset);
    Minute = mainmemory.readbyte(MinuteCurrentOffset);
    MinuteNext = mainmemory.readbyte(MinuteNextOffset);
    FrameCount = mainmemory.read_s32_le(FrameCountOffset);
    Height = client.bufferheight();
    Width = client.bufferwidth();
end;

-- this doesn't work correctly
-- but it's funny
local function quick_net(j)
    if JoypadState[Button.P1R1] then
        if mainmemory.readbyte(0x24BAC) == 0 and mainmemory.read_u16_le(0x027778) == 0x6C58 then
            mainmemory.write_u16_le(0x027778, 0x6F10)
            mainmemory.write_u8(0x24BAC, 1)
        else
            mainmemory.write_u16_le(0x027778, 0x6C58)
            mainmemory.write_u8(0x24BAC, 0)
        end
    end
end

local function HudPageDraw()
    -- exit early if there's nothing to draw
    if #HudPageDrawFns < 1 then return; end;
    local drawPage = true;
    local hudPageExitFnPrev = HudPageExitFns[HudPagePrevious];
    local hudPageInitFn = HudPageInitFns[HudPage];

    if (HudPagePrevious >= 1 and HudPage < 1) or (GameModePrevious ~= Mode.StartUp and GameMode == Mode.StartUp) then
        drawPage = false;
        -- run previous exit function and don't render if we moved from hud to no hud state
        if hudPageExitFnPrev ~= nil then hudPageExitFnPrev() end;
    elseif (HudPagePrevious < 1 and HudPage >= 1) or (GameModePrevious == Mode.StartUp and GameMode ~= Mode.StartUp) then
        drawPage = true;
        -- run entry function and render if we moved from no hud to hud state
        if hudPageInitFn ~= nil then hudPageInitFn() end;
    elseif HudPagePrevious ~= HudPage then
        drawPage = true;
        -- run previous exit function, page init function, and render if page changed
        if hudPageExitFnPrev ~= nil then hudPageExitFnPrev() end;
        if hudPageInitFn ~= nil then hudPageInitFn() end;
    end;

    -- draw page name
    if drawPage and HudPageNames[HudPage] ~= nil then
        gui.drawText(2, Height  - 15, HudPageNames[HudPage], nil, nil);
    end;

    -- draw page
    if drawPage and HudPageDrawFns[HudPage] ~= nil then
        for _, drawFunc in ipairs(HudPageDrawFns[HudPage]) do
            drawFunc();
        end;
    end;
end;

----------------------- Main


AddPage("Clock", nil, nil,
    DrawClock
);

AddPage("Story", nil, nil,
    DrawClock, 
    DrawStoryEventFlags, 
    DrawBeehiveStatus, 
    DrawTreeChopStatus, 
    DrawFlowersStatus
);

AddPage("Bugs on Screen", nil, nil,
    DrawClock, 
    DrawOnScreenBugs
);

AddPage("Screen Timer", InitTimer, InitTimer,
    DrawClock,
    DrawTimer
);

AddPage("Sumo", nil, nil,
    DrawClock,
    DrawFightersStats,
    DrawCdPos,
    DrawSumoStats
);

AddPage("Sumo Inventories", nil, nil,
    DrawClock,
    DrawBugInventories,
    DrawSumoStats
);

--#region Menu

local HudMenuCursorPos = 0;
local MenuType = {
    BoolHoriz = 1,
    SelectHoriz = 2,
    EditHoriz = 3
}

local Menu = { 
    Items = {};
    Parent = nil;
    SelectedOption = 1;
};


local PageLabels = {};
local PageValues = {};

for index, value in ipairs(HudPageNames) do
    table.insert(PageValues, index)
    table.insert(PageLabels, value)
end
local MenuItemHubPage = {
    Name = "Hud Page",
    Type = MenuType.SelectHoriz,
    Selected = false,
    SelectOptions = PageLabels,
    SelectValues = PageValues,
    SelectedValue = HudPage,
    Parent = Menu.Items
};
MenuItemHubPage.OnOpened = function() 
    MenuItemHubPage.SelectedValue = HudPage
end;
MenuItemHubPage.OnSave = function() HudPage = MenuItemHubPage.SelectedValue; end;
table.insert(Menu.Items, MenuItemHubPage)

local MenuItemHour = {
    Name = "Set Hour";
    Selected = false;
    Parent = Menu.Items;
    Type = MenuType.EditHoriz;
    SelectedValue = nil;
    Min = 0;
    Max = 255;
}
MenuItemHour.OnOpened = function() MenuItemHour.SelectedValue = Hour end;
MenuItemHour.OnSave = function() 
    if MenuItemHour.SelectedValue ~= Hour then
        mainmemory.writebyte(HourCurrentOffset, MenuItemHour.SelectedValue);
    end
end;
table.insert(Menu.Items, MenuItemHour);

local MenuItemMinute = {
    Name = "Set Minute";
    Selected = false;
    Parent = Menu.Items;
    Type = MenuType.EditHoriz;
    SelectedValue = nil;
    Min = 0;
    Max = 255;
}
MenuItemMinute.OnOpened = function() MenuItemMinute.SelectedValue = Minute; end;
MenuItemMinute.OnSave = function() 
    if MenuItemMinute.SelectedValue ~= Minute then
        mainmemory.writebyte(MinuteCurrentOffset, MenuItemMinute.SelectedValue);
    end
end;
table.insert(Menu.Items, MenuItemMinute);

local MenuItemTimeFreeze = {
    Name = "Freeze Time",
    Type = MenuType.BoolHoriz,
    Selected = false;
    SelectedValue = TimeFreeze;
    Parent = Menu.Items;
};
MenuItemTimeFreeze.OnOpened = function() MenuItemTimeFreeze.SelectedValue = TimeFreeze; end;
MenuItemTimeFreeze.OnSave = function()
    if MenuItemTimeFreeze.SelectedValue then
        -- this is going to work because it runs after the time save methods
        TimeFreezeValue = mainmemory.readbyte(MinuteCurrentOffset);
        TimeFreeze = true;
    else
        TimeFreeze = false;
    end
end;
table.insert(Menu.Items, MenuItemTimeFreeze);



local MenuItemLuck = {
    Name = "Set Luck";
    Selected = false;
    Parent = Menu.Items;
    Type = MenuType.EditHoriz;
    SelectedValue = nil;
    Min = 0;
    Max = 255;
}
MenuItemLuck.OnOpened = function() MenuItemLuck.SelectedValue = mainmemory.readbyte(LuckOffset); end;
MenuItemLuck.OnSave = function()
    mainmemory.writebyte(LuckOffset, MenuItemLuck.SelectedValue);
end;
table.insert(Menu.Items, MenuItemLuck);

local MenuItemBlank = {
    Name = "",
    -- Type = MenuType.BoolHoriz,
    Selected = false;
    -- SelectDefault = TimeFreeze;
    -- SelectedValue = TimeFreeze;
    Parent = Menu.Items;
};
table.insert(Menu.Items, MenuItemBlank)

local Instruction = {
    Name = "Select/◎ = Save ⓧ = Cancel",
    -- Type = MenuType.BoolHoriz,
    Selected = false;
    -- SelectDefault = TimeFreeze;
    -- SelectedValue = TimeFreeze;
    Parent = Menu.Items;
};
table.insert(Menu.Items, Instruction)

local function SetBounded(val, min, max, adj)
    if val + adj < min then
        return max;
    elseif val + adj > max then
        return min;
    else
        return val + adj;
    end;
end;

local function HudMenuDraw()
    DrawClock();
    local x1 = Width / 8
    local y1 = Height / 8
    local x2 = x1 + ((Width / 8) * 6)
    local y2 = y1 + ((Height / 8) * 6)
    gui.drawBox(x1, y1, x2, y2, nil, "#F0000000")

    if JoypadState[Button.P1Up] == ButtonState.Pressed then
        Menu.SelectedOption = SetBounded(Menu.SelectedOption, 1, #Menu.Items, -1)
    elseif JoypadState[Button.P1Down] == ButtonState.Pressed then
        Menu.SelectedOption = SetBounded(Menu.SelectedOption, 1, #Menu.Items, 1)
    end

    local left = x1 + 11;
    local top = y1 + 11;
    for index, value in pairs(Menu.Items) do
        local item = value;
        local selected = Menu.SelectedOption == index;
        local itemLine = "" .. (selected and "->" or "  ") .. item.Name;
        if item.Type == MenuType.SelectHoriz then
            local selectPart = "";
            if selected then selectPart = "<" else selectPart = " " end
            if selected then
                if JoypadState[Button.P1Left] == ButtonState.Pressed then
                    item.SelectedValue = SetBounded(item.SelectedValue, 1, #item.SelectValues, -1)
                elseif JoypadState[Button.P1Right] == ButtonState.Pressed then
                    item.SelectedValue = SetBounded(item.SelectedValue, 1, #item.SelectValues, 1)
                end
            end;
            selectPart = selectPart .. item.SelectOptions[item.SelectedValue]
            if selected then selectPart = selectPart .. ">" else selectPart = selectPart .. " " end;
            itemLine = itemLine .. bizstring.pad_start(selectPart, 30 - string.len(itemLine), " ") 
        elseif item.Type == MenuType.BoolHoriz then
            local selectPart = "";
            if selected then selectPart = "<" else selectPart = " " end
            if selected then
                if JoypadState[Button.P1Left] == ButtonState.Pressed then
                    item.SelectedValue = not item.SelectedValue
                elseif JoypadState[Button.P1Right] == ButtonState.Pressed then
                    item.SelectedValue = not item.SelectedValue
                end
            end
            selectPart = selectPart .. (item.SelectedValue and "On" or "Off")
            if selected then selectPart = selectPart .. ">" else selectPart = selectPart .. " " end;
            itemLine = itemLine .. bizstring.pad_start(selectPart, 30 - string.len(itemLine), " ")
        elseif item.Type == MenuType.EditHoriz then
            local selectPart = "";
            if selected then selectPart = "<" else selectPart = " " end
            if selected then
                if JoypadState[Button.P1Left] == ButtonState.Pressed then
                    item.SelectedValue = SetBounded(item.SelectedValue, item.Min, item.Max, -1)
                elseif JoypadState[Button.P1Right] == ButtonState.Pressed then
                    item.SelectedValue = SetBounded(item.SelectedValue, item.Min, item.Max, 1)
                end
            end
            selectPart = selectPart .. tostring(item.SelectedValue)
            if selected then selectPart = selectPart .. ">" else selectPart = selectPart .. " " end;
            itemLine = itemLine .. bizstring.pad_start(selectPart, 30 - string.len(itemLine), " ")
        end
        gui.drawText(left, top + (index * 11), itemLine, "#FFFFFFFF", "#00000000")
    end
end

local function ToggleMode5Pause(shouldPause)
    if GameMode == Mode.Game then
        if shouldPause then
            mainmemory.writebyte(PauseStateOffset, 1)
            mainmemory.writebyte(PauseAnimationStateOffset, 0)
            mainmemory.writebyte(PauseAnimationTimerOffset, 15)
        else
            mainmemory.writebyte(PauseStateOffset, 0)
            mainmemory.writebyte(PauseAnimationStateOffset, 2)
            mainmemory.writebyte(PauseAnimationTimerOffset, 0)
        end
    end
end;

local function OnMenuSave()
    for _, item in ipairs(Menu.Items) do
        if item.OnSave ~= nil then
            item.OnSave();
        end;
    end;
end;
local function OnMenuCancel()
    for _, item in ipairs(Menu.Items) do
        if item.OnCancel ~= nil then
            item.OnCancel();
        end;
    end;
end;
local function OnMenuOpened()
    Menu.SelectedOption = 1
    for _, item in ipairs(Menu.Items) do
        if item.OnOpened ~= nil then
            item.OnOpened();
        end;
    end;
end;

local function HudMenuUpdateState()
    if JoypadState[Button.P1Select] == ButtonState.Pressed then
        if HudMenuOpen then
            HudMenuOpen = false;
            ToggleMode5Pause(false)
            OnMenuSave()
        else
            OnMenuOpened();
            ToggleMode5Pause(true);
            HudMenuOpen = true;
        end
    elseif HudMenuOpen and JoypadState[Button.P1Cicle] == ButtonState.Pressed then
        HudMenuOpen = false;
        ToggleMode5Pause(false)
        OnMenuSave()
    elseif HudMenuOpen and JoypadState[Button.P1Cross] == ButtonState.Pressed then
        HudMenuOpen = false;
        ToggleMode5Pause(false)
        OnMenuCancel();
    end;
end;
--#endregion

---Main loop
while true do
    gui.defaultBackground("#ff000000")
    gui.defaultForeground("#ffffffff")
    if TimeFreeze and TimeFreezeValue ~= nil then
        mainmemory.writebyte(MinuteNextOffset, TimeFreezeValue)
    end
    UpdateGlobals()
    if JoypadState[Button.P1R1] == ButtonState.Pressed then
        HudPage = SetBounded(HudPage, 1, #HudPageNames, 1)
        -- item.SelectedValue = SetBounded(item.SelectedValue, 1, #item.SelectValues, 1)
    end;
    HudMenuUpdateState()
    if HudMenuOpen then
        HudMenuDraw();
    else
        HudPageDraw();
    end;
    emu.frameadvance();
end

local M = {}

-- ===== Formatting helpers =====
function M.fmtDuration(s)
   if s == nil then return "n/a" end
   local n = tonumber(s)
   if n == nil then return tostring(s) end
   if math.abs(n) < 0.0001 then return string.format("%.1f us", n * 1e6) end
   if math.abs(n) < 0.1 then return string.format("%.2f ms", n * 1e3) end
   return string.format("%.3f s", n)
end

function M.fmtRate(bitsPerSec)
   if bitsPerSec == nil then return "n/a" end
   local b = tonumber(bitsPerSec)
   if b == nil then return tostring(bitsPerSec) end
   if b < 1000 then return string.format("%.1f bit/s", b) end
   if b < 1e6 then return string.format("%.2f Kbit/s", b / 1e3) end
   if b < 1e9 then return string.format("%.2f Mbit/s", b / 1e6) end
   return string.format("%.2f Gbit/s", b / 1e9)
end

-- ===== Path formatting =====
function M.shortenIA(ia)
   if type(ia) ~= "string" then return tostring(ia) end
   local asOnly = ia:match("^%d+%-(.+)$")
   return asOnly or ia
end

local function getInterfaceIA(interface)
   if type(interface) == "table" then
      return interface.IA or interface.IsdAs or interface.AS
   elseif type(interface) == "string" then
      return interface
   end
   return nil
end

function M.formatInterfaces(interfaces)
   if type(interfaces) ~= "table" then return "no interfaces" end
   local chain = {}
   for _, interface in ipairs(interfaces) do
      local ia = getInterfaceIA(interface)
      if ia then
         local short = M.shortenIA(ia)
         if #chain == 0 or chain[#chain] ~= short then
            table.insert(chain, short)
         end
      end
   end
   if #chain == 0 then return "empty path" end
   return table.concat(chain, " -> ")
end

-- ===== Statistics table =====
local function pad(s, width)
   s = tostring(s)
   if #s >= width then return s end
   return s .. string.rep(" ", width - #s)
end

local MAX_PATH_HEADER = 80
-- S: sum; R: reordering; T: timeout (loss type)
local STAT_LABELS = { "Path", "Active#", "S", "R", "T", "Loss%(SBD)", "SmRTT", "AvgTP", "SBD-TP" }

local function pathHops(r)
   if type(r.hops) == "number" then return r.hops end
   local s = r.pathString or ""
   local count = 0
   for _ in s:gmatch(" %-> ") do count = count + 1 end
   return count + 1
end

function M.printStatsTable(rows)
   if #rows == 0 then return end

   local sorted = {}
   for i, r in ipairs(rows) do sorted[i] = r end
   table.sort(sorted, function(a, b)
      local ha, hb = pathHops(a), pathHops(b)
      if ha ~= hb then return ha < hb end
      return (a.pathString or "") < (b.pathString or "")
   end)

   local cellRows = {}
   for _, r in ipairs(sorted) do
      local ph = r.pathString or "n/a"
      if #ph > MAX_PATH_HEADER then
         ph = ph:sub(1, MAX_PATH_HEADER - 3) .. "..."
      end
      ph = (r.active and "* " or "  ") .. ph
      local agg = r.agg or {}
      local sbdConnectionInfo = r.sbdConnectionInfo
      table.insert(cellRows, {
         ph,
         tostring(r.usageCount or 0),
         tostring(agg.lossSum or 0),
         tostring(agg.lossReorder or 0),
         tostring(agg.lossTimeout or 0),
         sbdConnectionInfo and (string.format("%.2f", sbdConnectionInfo.PacketLoss) .. " %") or "n/a",
         M.fmtDuration(agg.smoothedRTT),
         M.fmtRate(agg.avgThroughput),
         -- sbdConnectionInfo.Throughput is bytes/s; fmtRate expects bits/s
         sbdConnectionInfo and M.fmtRate(sbdConnectionInfo.Throughput * 8) or "n/a",
      })
   end

   local colWidth = {}
   for ci, label in ipairs(STAT_LABELS) do
      colWidth[ci] = #label
   end
   for _, cr in ipairs(cellRows) do
      for ci = 1, #STAT_LABELS do
         if #cr[ci] > colWidth[ci] then colWidth[ci] = #cr[ci] end
      end
   end

   local function hline()
      local parts = {}
      for ci = 1, #STAT_LABELS do table.insert(parts, string.rep("-", colWidth[ci] + 2)) end
      return "+" .. table.concat(parts, "+") .. "+"
   end
   local function row(cellValues)
      local parts = {}
      for ci = 1, #STAT_LABELS do table.insert(parts, " " .. pad(cellValues[ci], colWidth[ci]) .. " ") end
      return "|" .. table.concat(parts, "|") .. "|"
   end

   local lines = { hline(), row(STAT_LABELS), hline() }
   for _, cr in ipairs(cellRows) do
      table.insert(lines, row(cr))
   end
   table.insert(lines, hline())

   panapi.Log("\n" .. table.concat(lines, "\n"))
end

return M
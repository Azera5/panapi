local utils = require("utils")

-- ===== Configuration =====
BOTTLENECK_REPORT_INTERVAL = 1    -- seconds between bottleneck reports
STATISTICS_REPORT_INTERVAL = 5    -- seconds between per-path statistics tables
PATH_PREFERENCE = "longest"       -- "shortest" | "longest" | "random"
AVOID_BOTTLENECKS = true          -- prefer fewer shared bottlenecks over PATH_PREFERENCE
PATH_SWITCH_INTERVAL = 3          -- seconds between active-path switches 


-- ===== State =====
paths = {}            -- [raddr]
activePath = {}       -- [laddr.."|"..raddr] -> {path, lastSwitchTime, laddr, raddr, isActive}
pathStatistics = {}   -- [fingerprint]

local function countSharedBottlenecks(path, bottleneckInterfaces)
   -- Get the correct interface structure for multi-/ single-connection
   local interfaces =
         (path.Metadata and path.Metadata.Interfaces)  -- single-connections
      or path.Interfaces                               -- multi-connections
      or {}

   local count = 0
   for _, interface in ipairs(interfaces) do
      local ia    = interface.IA    or interface.ia
      local if_id = interface.IfID  or interface.if_id

      for _, bottleneck in ipairs(bottleneckInterfaces) do
         local b_ia    = bottleneck.IA    or bottleneck.ia
         local b_if_id = bottleneck.IfID  or bottleneck.if_id

         if ia == b_ia and if_id == b_if_id then
            count = count + 1
            break
         end
      end
   end
   return count
end

local function rankpaths(paths, bottleneckInterfaces)
   local useBottlenecks = AVOID_BOTTLENECKS and bottleneckInterfaces ~= nil 
   for _, path in ipairs(paths) do
      if useBottlenecks then
         path._bottleneckCount = countSharedBottlenecks(path, bottleneckInterfaces)         
      else
         path._bottleneckCount = 0
      end
     
      if PATH_PREFERENCE == "shortest" then
         path._preferenceKey = #path.Metadata.Interfaces
      elseif PATH_PREFERENCE == "longest" then
         path._preferenceKey = -#path.Metadata.Interfaces
      else
         path._preferenceKey = math.random()
      end

      path._tieBreaker = math.random()
   end


   table.sort(paths, function(path_a, path_b)
      if path_a._bottleneckCount ~= path_b._bottleneckCount then
         return path_a._bottleneckCount < path_b._bottleneckCount
      end
      if path_a._preferenceKey ~= path_b._preferenceKey then
         return path_a._preferenceKey < path_b._preferenceKey
      end
      return path_a._tieBreaker < path_b._tieBreaker
   end)
   return paths
end

local function getWeightedIndex(count)
   if count <= 1 then return 1 end

   local index = math.floor(1 / math.sqrt(math.random()))
   
   if index > count then index = ((index - 1) % count) + 1 end
   return index
end

local function recordPathStatistics(fp, path, laddr, raddr)
   local statistic = pathStatistics[fp]
   if not statistic then
      statistic = {
         pathDescription = utils.formatInterfaces(path.Metadata.Interfaces),
         selectedCount = 0,
         reorderLossCount = 0,
         timeoutLossCount = 0,
         smoothedRTT = 0,
         throughputSum = 0,
         throughputSamples = 0,
      }
      pathStatistics[fp] = statistic
   end
   statistic.selectedCount = statistic.selectedCount + 1

   if laddr and raddr then
      local info = panapi.ConnectionInfo(laddr, raddr)
      if info then
         statistic.lastsbdConnectionInfo = info

         if info.Throughput and info.Throughput > 0 then
            statistic.throughputSum = statistic.throughputSum + (info.Throughput * 8) -- bits/sec needed but getting bytes/s
            statistic.throughputSamples = statistic.throughputSamples + 1
         end

      end
   end
end

-- ===== panapi callbacks =====
function panapi.Initialize(prefs, laddr, raddr, ps)
   panapi.Log("New connection [" .. laddr, "|", raddr .. "]")
   paths[raddr] = ps
end

function panapi.Setprefs(prefs, laddr, raddr) end

function panapi.Refresh(laddr, raddr, ps)
   paths[raddr] = ps
end

function panapi.PathDown(laddr, raddr, fp, pathInfo)
   local pool = paths[raddr]
   if not pool then return end
   for index, path in ipairs(pool) do
      if path.Fingerprint == fp then
         table.remove(pool, index)
         return
      end
   end
end

function panapi.Path(laddr, raddr)
   local pool = paths[raddr]
   if not pool or #pool == 0 then return nil end

   -- single-connections: switches here after PATH_SWITCH_INTERVAL
   -- multi-connections:  called only for initial connection, switches uses SelectActivePath
   local connKey = laddr .. "|" .. raddr
   local now = os.time()

   local state = activePath[connKey]
   if state and (now - state.lastSwitchTime) < PATH_SWITCH_INTERVAL then
      for _, p in ipairs(pool) do
         if p.Fingerprint == state.path.Fingerprint then
            state.path = p
            return p
         end
      end
   end

   -- Prefer paths that no other connection to raddr uses yet (needed for multi-connections)
   local used = {}
   for key, s in pairs(activePath) do
      if s.raddr == raddr and key ~= connKey then used[s.path.Fingerprint] = true end
   end
   local candidates = {}
   for _, p in ipairs(pool) do
      if not used[p.Fingerprint] then candidates[#candidates + 1] = p end
   end
   if #candidates == 0 then
      for _, p in ipairs(pool) do candidates[#candidates + 1] = p end
   end

   local rankedPaths = rankpaths(candidates, nil)
   local selectedPath = rankedPaths[getWeightedIndex(#rankedPaths)]
   activePath[connKey] = {path = selectedPath, lastSwitchTime = now, laddr = laddr, raddr = raddr, isActive = true}
   recordPathStatistics(selectedPath.Fingerprint, selectedPath, laddr, raddr)

   panapi.Log("[path switched] " .. utils.formatInterfaces(selectedPath.Metadata.Interfaces))
   return selectedPath
end

function pinnedPaths(raddr, current)
   local pool = paths[raddr]
   if not pool or #pool == 0 or not current or #current == 0 then
      return {}
   end

   local wanted = {}
   for i = 1, #current do wanted[current[i]] = true end

   local filtered = {}
   for i = 1, #pool do
      local p = pool[i]
      if wanted[p.Fingerprint] then
         filtered[#filtered + 1] = p
      end
   end

   return filtered
end

function panapi.SelectActivePath(raddr, current)  
   if #current == 0 then
      activePath[raddr] = nil
      return nil
   end

   -- state will be the most recently switched entry of this raddr
   local state
   for _, s in pairs(activePath) do
      if s.raddr == raddr and (not state or s.lastSwitchTime > state.lastSwitchTime) then state = s end
   end
   local now = os.time()
   local bottleneck = panapi.BottleneckInterfaces()

   -- skip  path switching only if AVOID_BOTTLENECKS is false or no bottleneck was detected
   if state and state.path and state.lastSwitchTime and (now - state.lastSwitchTime) < PATH_SWITCH_INTERVAL and (not AVOID_BOTTLENECKS or #bottleneck==0) then
      return nil
   end
   
   local pathPool = pinnedPaths(raddr, current)
   local clean, affected = panapi.FilterBottlenecked(pathPool)

   local rankedClean    = rankpaths(clean, bottleneck)
   local rankedAffected = rankpaths(affected, bottleneck)
   local rankedPaths = {}
   for _, p in ipairs(rankedClean)    do table.insert(rankedPaths, p) end
   for _, p in ipairs(rankedAffected) do table.insert(rankedPaths, p) end
   local selectedPath = rankedPaths[getWeightedIndex(#rankedPaths)]
   if not selectedPath then return nil end
   
   -- find the selected path by its fingerprint and mark it as active, necessary because laddrs is unknown within SelectActivePath
   local selectedState
   for _, s in pairs(activePath) do
      if s.raddr == raddr then
         s.isActive = nil
         if s.path.Fingerprint == selectedPath.Fingerprint then selectedState = s end
      end
   end

   if not selectedState then return nil end
   selectedState.isActive = true
   selectedState.lastSwitchTime = now
   recordPathStatistics(selectedPath.Fingerprint, selectedPath, selectedState.laddr, raddr)

   panapi.Log("[active path switched] " .. utils.formatInterfaces(selectedPath.Metadata.Interfaces))
   return selectedPath.Fingerprint
end

function panapi.Close(laddr, raddr)
   activePath[laddr .. "|" .. raddr] = nil
   -- printStatisticsTable()
end

-- ===== stats =====
function stats.StartedConnection(laddr, raddr, srcConnID, destConnId) end
function stats.SentPacket(laddr, raddr) end
function stats.AcknowledgedPacket(laddr, raddr) end

function stats.UpdatedMetrics(laddr, raddr, rttStats, congestionWindow, bytesInFlight, packetsInFlight)
   local state = activePath[laddr .. "|" .. raddr]
   local statistic = state and pathStatistics[state.path.Fingerprint]
   if not statistic then 
      return end

   local smrtt = type(rttStats) == "table" and rttStats.SmoothedRTT
   if not (smrtt and smrtt > 0) then return end

   statistic.smoothedRTT = smrtt
end

function stats.LostPacket(laddr, raddr, encryptionLevel, packetNumber, lossReason)
   local state = activePath[laddr .. "|" .. raddr]
   local statistic = state and pathStatistics[state.path.Fingerprint]
   if not statistic then return end

   if lossReason == 0 then
      statistic.reorderLossCount = statistic.reorderLossCount + 1
   else
      statistic.timeoutLossCount = statistic.timeoutLossCount + 1
   end
end

function printBottleneckReport()
   local bottleneckInterfaces = panapi.BottleneckInterfaces()
   if #bottleneckInterfaces == 0 then return end

   for i, interface in ipairs(bottleneckInterfaces) do
      panapi.Log(
         "Bottleneck[" .. i .. "]: IA=" .. tostring(interface.IA) ..
         ", IfID=" .. tostring(interface.IfID)
      )
   end
end

function printStatisticsTable()
   local connectionForFingerprint, activeFingerprints = {}, {}
   for _, state in pairs(activePath) do
      if state.isActive then activeFingerprints[state.path.Fingerprint] = true end
      connectionForFingerprint[state.path.Fingerprint] = { laddr = state.laddr, raddr = state.raddr }
   end

   local rows = {}
   for fp, statistic in pairs(pathStatistics) do
         table.insert(rows, {
            pathString = statistic.pathDescription,
            usageCount = statistic.selectedCount,
            active = activeFingerprints[fp],
            sbdConnectionInfo = statistic.lastsbdConnectionInfo,
            agg = {
               lossSum = statistic.reorderLossCount + statistic.timeoutLossCount,
               lossReorder = statistic.reorderLossCount,
               lossTimeout = statistic.timeoutLossCount,
               smoothedRTT = statistic.smoothedRTT,
               avgThroughput = statistic.throughputSamples > 0 and (statistic.throughputSum / statistic.throughputSamples) or nil,
            },
         })
   end
   utils.printStatsTable(rows)
end

local secondsSinceBottleneckReport, secondsSinceStatisticsReport = 0, 0
function panapi.Periodic(seconds)
   secondsSinceBottleneckReport = secondsSinceBottleneckReport + seconds
   secondsSinceStatisticsReport = secondsSinceStatisticsReport + seconds

   if secondsSinceStatisticsReport >= STATISTICS_REPORT_INTERVAL then
      secondsSinceStatisticsReport = 0
      printStatisticsTable()
   end

   if secondsSinceBottleneckReport >= BOTTLENECK_REPORT_INTERVAL then
      secondsSinceBottleneckReport = 0
      printBottleneckReport()
   end
end
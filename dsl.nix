{ lib, notnft }:

let
  isSpecial = x: builtins.isAttrs x && builtins.any (lib.hasPrefix "__") (builtins.attrNames x);
  fixupStmts = stmts:
    if builtins.isList stmts then map fixupStmts stmts
    else if !(builtins.isAttrs stmts) then stmts
    else if stmts?__expr__ then fixupStmts stmts.__expr__
    else if builtins.any (lib.hasPrefix "_") (builtins.attrNames stmts) then stmts
    else builtins.mapAttrs (k: fixupStmts) stmts;
  fillEnum = enum: x: if builtins.isFunction x then x enum else x;
  fillEnums = enums: builtins.mapAttrs (k: v: if builtins.isFunction v then v enums.${k} else v);
  mkObj = name: enums: attrs:
    fillEnums (fillEnum attrs (fillEnum attrs enums)) attrs;
  # takeAttrs = names: lib.filterAttrs (k: v: builtins.elem k names);
  finalize = attrs: x:
    if x?__finalize then x.__finalize x attrs
    else fillEnum attrs x;
  mkCmd = cmd': obj0:
    if obj0 == self.existing then obj0: mkCmd cmd' (obj0 // { __existing__ = true; _ = null; }) else (let
      family = { family = notnft.families; };
      family2 = { type, ... }:
      let
        t = notnft.chainTypes.${toString (fillEnum notnft.chainTypes type)};
        families = if t?families then lib.filterAttrs (k: v: builtins.elem k t.families) notnft.families else notnft.families;
      in { family = families; };
      ctype = { type = notnft.chainTypes; };
      hook = { hook = notnft.hooks; };
      hook2 = { type, ... }:
      let
        t = notnft.chainTypes.${toString (fillEnum notnft.chainTypes type)};
        hooks = if t?hooks then lib.filterAttrs (k: v: builtins.elem k t.hooks) notnft.hooks else notnft.hooks;
      in { hook = hooks; };
      cpolicy = { policy = notnft.chainPolicies; };
      cprio = { family ? null, hook ? null, ... }:
        let
          family' = toString (fillEnum notnft.families family);
          hook' = toString (fillEnum notnft.hooks hook);
        in {
          prio = builtins.mapAttrs
            (k: v: v.value family')
            (lib.filterAttrs
              (k: v:
                (!v?families || builtins.elem family' v.families)
                && (!v?hooks || builtins.elem hook' v.hooks))
              notnft.chainPriorities);
        };
      fprio = { prio = notnft.flowtablePriorities; };
      spolicy = { policy = notnft.setPolicies; };
      stype = { type = notnft.setKeyTypes; };
      map' = { map = notnft.nftTypes; };
      sflags = { flags = notnft.setFlags; };
      protocol = { protocol = notnft.ctProtocols; };
      l3proto = { l3proto = notnft.l3Families; };
      per = { per = notnft.timeUnits; };
      rate_unit = { rate_unit = notnft.rateUnits; };
      burst_unit = { burst_unit = notnft.rateUnits; };
      spflags = { flags = notnft.synproxyFlags; };
      obj = obj0.__object__ or obj0;
      existing = obj0.__existing__ or false;
      initial = obj0.__initial__ or { };
      cmd = if cmd' == "insert" && obj != "rule" then "add" else cmd';
      obj' =
        if obj == "table" then mkObj "table" family
        else if obj == "chain" then mkObj "chain" (attrs: family2 attrs // ctype // hook2 attrs // cpolicy // cprio attrs)
        else if obj == "rule" then mkObj "rule" family
        else if obj == "set" then mkObj "set" (family // spolicy // stype // sflags)
        else if obj == "map" then mkObj "map" (family // spolicy // stype // sflags // map')
        else if obj == "flowtable" then mkObj "flowtable" family // hook // fprio
        else if obj == "counter" then mkObj "counter" family
        else if obj == "quota" then mkObj "quota" family
        else if obj == "ct helper" then mkObj "ct helper" (family // protocol // l3proto)
        else if obj == "limit" then mkObj "limit" (family // per // rate_unit // burst_unit)
        else if obj == "ct timeout" then mkObj "ct timeout" (family // protocol // l3proto)
        else if obj == "ct expectation" then mkObj "ct expectation" (family // l3proto // protocol)
        else if obj == "synproxy" then mkObj "synproxy" (family // spflags)
        else mkObj obj { };
      extend =
        if cmd' == "insert" then a: b: lib.toList b ++ a
        else a: b: a ++ lib.toList b;
    in
      if obj == "table" then let fn = initial: {
        __list__ = [ ];
        __attrs__ = { };
        __functor = self: x:
          if isSpecial x then self // { __list__ = self.__list__ ++ lib.toList x; }
          else if builtins.isList x then self // { __list__ = builtins.concatLists ([ self.__list__ ] ++ map lib.toList x); }
          else self // { __attrs__ = self.__attrs__ // x; };
        __finalize = self: attrs:
          let
            obj'' = initial // fillEnum (initial // attrs) obj';
          in
            builtins.concatLists (lib.optional (!existing) [ { ${cmd}.table = obj''; } ]
            ++ (map (x: lib.toList (finalize {
              inherit (obj'') family;
              table = obj''.name;
            } x)) self.__list__)
            ++ (lib.mapAttrsToList (k: v: lib.toList (finalize {
              inherit (obj'') family;
              table = obj''.name;
              name = k;
            } v)) self.__attrs__));
      }; in fn initial // {
        __functor = self: arg: if !(isSpecial arg) && (arg?comment || arg?family || arg?name || arg?handle) then fn (initial // arg) else fn initial arg;
      } else if obj == "chain" then let fn = initial: {
        __list__ = [ ];
        __functor = self: x:
          if isSpecial x then self // { __list__ = extend self.__list__ x; }
          else if x == [] || builtins.isList (builtins.head x) then self // {
            __list__ = builtins.foldl' (a: b: extend a [ b ]) self.__list__ x;
          } else self // {
            __list__ = extend self.__list__ [ x ];
          };
        __finalize = self': attrs:
          let
            obj'' = initial // fillEnum (initial // attrs) obj';
          in
            builtins.concatLists (lib.optional (!existing) [ { ${cmd}.chain = obj''; } ]
            ++ map (x:
              lib.toList (if builtins.isList x then (finalize { } (mkCmd cmd' self.rule {
                inherit (obj'') family table;
                chain = obj''.name;
                expr = fixupStmts x;
              })) else let tmp = finalize ({
                inherit (obj'') family table;
                chain = obj''.name;
              }) x; in tmp // { expr = fixupStmts tmp.expr; })) self'.__list__);
      }; in fn initial // {
        __functor = self: arg: if !(isSpecial arg) && builtins.any (field: arg?${field}) [ "family" "table" "name" "type" "hook" "prio" "dev" "policy" "comment" "handle" "newname" ] then fn (initial // arg) else fn initial arg;
      } else if obj == "set" || obj == "map" then let fn = initial: {
        __list__ = [ ];
        __functor = self: x: self // {
          __list__ = self.__list__ ++ x;
        };
        __finalize = self: args:
          let
            obj'' = initial // fillEnum (initial // args) obj';
          in
            if existing then {
              ${cmd}.element = {
                inherit (obj'') family table name;
                elem = map fixupStmts self.__list__;
              };
            } else {
              ${cmd}.${obj} = obj'' // {
                elem = map fixupStmts self.__list__;
              };
            };
      }; in fn initial // {
        __functor = self: arg:
          if !(isSpecial arg) && builtins.isAttrs arg && builtins.any (field: arg?${field}) [ "table" "name" "type" "map" "policy" "flags" "elem" "timeout" "gc-interval" "size" "stmt" "handle" ] then fn (initial // arg) else fn initial arg;
      } else {
        __functor = self: args: let initial' = initial // args; in {
          __finalize = self: args: {
            ${cmd}.${obj} = initial' // fillEnum (initial' // args) obj';
          };
        };
        __finalize = self: args: {
          ${cmd}.${obj} = initial // fillEnum (initial // args) obj';
        };
      });
    
self = rec {
  create = mkCmd "create";
  add = mkCmd "add";
  insert = mkCmd "insert";
  delete = mkCmd "delete";
  destroy = mkCmd "destroy";
  flush = mkCmd "flush";
  rename = mkCmd "rename";
  table = {
    __object__ = "table";
    __functor = add;
  } // builtins.mapAttrs (k: v: {
    __object__ = "table";
    __initial__ = { family = v; };
  }) notnft.families;
  tables = { __object__ = "tables"; };
  existing = {
    __existing__ = true;
    __functor = self: x: mkCmd "add" (self // x);
  };
  rule = { __object__ = "rule"; };
  rules = { __object__ = "rules"; };
  chain = { __object__ = "chain"; };
  chains = { __object__ = "chains"; };
  set = { __object__ = "set"; };
  sets = { __object__ = "sets"; };
  maps = { __object__ = "maps"; };
  flowtable = { __object__ = "flowtable"; };
  flowtables = { __object__ = "flowtables"; };
  synproxys = { __object__ = "synproxys"; };
  counter = { __object__ = "counter"; };
  quotas = { __object__ = "quotas"; };
  secmarks = { __object__ = "secmarks"; };
  ctHelpers = { __object__ = "ct helpers"; };
  ctTimeouts = { __object__ = "ct timeouts"; };
  ctExpectations = { __object__ = "ct expectations"; };
  meters = { __object__ = "meters"; };
  counters = { __object__ = "counters"; };
  ruleset = {
    __object__ = "ruleset";
    __functor = self: attrs: {
      nftables =
        if builtins.isAttrs attrs
        then builtins.concatLists (lib.mapAttrsToList
          (name: val: lib.toList (finalize { inherit name; } val))
          attrs)
        else assert builtins.isList attrs; builtins.concatLists (map lib.toList attrs);
    };
  };
  match = builtins.mapAttrs (_: op: left: right: {
    match = {
      inherit op left;
      right = fillEnum (notnft.exprEnumsMerged left) right;
    };
  }) notnft.operators // {
    __functor = self: self.auto;
  };
  is = match;

  ct = (builtins.mapAttrs (_: key: {
    ct.key = key;
  }) (lib.filterAttrs (k: v: (v.dir or true) != true && (v.family or true) != true) notnft.ctKeys)) // (lib.genAttrs [ "original" "reply" ] (dir':
    let dir = notnft.ctDirs.${dir'}; in (builtins.mapAttrs (_: key: {
      ct = { inherit key dir; };
    }) (lib.filterAttrs (k: v: (v.dir or true) != false && (v.family or true) != true) notnft.ctKeys)) // {
      ip.saddr.ct = { key = notnft.ctKeys."ip saddr"; inherit dir; };
      ip6.saddr.ct = { key = notnft.ctKeys."ip6 saddr"; inherit dir; };
      ip.daddr.ct = { key = notnft.ctKeys."ip daddr"; inherit dir; };
      ip6.daddr.ct = { key = notnft.ctKeys."ip6 daddr"; inherit dir; };
    }));

  numgen = builtins.mapAttrs (_: mode: attrs: ({ mod, offset ? null } @ attrs: {
    numgen = attrs // { inherit mode; };
  }) (if builtins.isAttrs attrs then attrs else { mod = attrs; })) notnft.ngModes;

  jhash = expr: attrs: ({ mod, offset ? null, seed ? null } @ attrs: {
    jhash = attrs // { inherit expr; };
  }) (if builtins.isAttrs attrs then attrs else { mod = attrs; });
  symhash = attrs: ({ mod, offset ? null } @ attrs: {
    symhash = attrs;
  }) (if builtins.isAttrs attrs then attrs else { mod = attrs; });

  payload = builtins.mapAttrs
    (_: proto:
      (builtins.mapAttrs (field: _: {
        payload = {
          protocol = proto;
          field = notnft.payloadFields.${field};
        };
      }) proto.fields))
    notnft.payloadProtocols;
  tcpOpt = builtins.mapAttrs
    (_: opt:
      (builtins.mapAttrs (field: _: {
        "tcp option" = {
          name = opt;
          field = notnft.tcpOptionFields.${field};
        };
      }) opt.fields) // {
        __expr__."tcp option".name = opt;
      })
    notnft.tcpOptions;
  ipOpt = builtins.mapAttrs
    (_: opt:
      (builtins.mapAttrs (field: _: {
        "ip option" = {
          name = opt;
          field = notnft.ipOptionFields.${field};
        };
      }) opt.fields) // {
        __expr__."ip option".name = opt;
      })
    notnft.ipOptions;
  sctpChunk = builtins.mapAttrs
    (_: chunk:
      (builtins.mapAttrs (field: _: {
        "sctp chunk" = {
          name = chunk;
          field = notnft.sctpChunkFields.${field};
        };
      }) chunk.fields) // {
        __expr__."sctp chunk".name = chunk;
      })
    notnft.sctpChunks;
  exthdr = builtins.mapAttrs
    (_: hdr:
      (builtins.mapAttrs (field: _: let val = {
        exthdr = {
          name = hdr;
          field = notnft.exthdrFields.${field};
        };
      }; in if field == "rt0" then {
        __expr__ = val;
        __functor = self: offset: self.__expr__ // { inherit offset; };
      } else val) hdr.fields) // {
        __expr__."tcp option".name = hdr;
      })
    notnft.exthdrs;
  bit = let
    self = (lib.genAttrs [ "|" "^" "&" "<<" ">>" ] (op: let fn = (a: b: {
      __expr__.${op} = [ a (fillEnum (notnft.exprEnumsMerged a) b) ];
      __functor = self: fn self.__expr__;
    }); in fn));
  in self // rec {
    or = self."|";
    xor = self."^";
    and = self."&";
    lsh = self."<<";
    rsh = self.">>";
    lshift = lsh;
    rshift = lsh;
  };
  meta = builtins.mapAttrs (_: key: {
    meta.key = key;
  }) notnft.metaKeys;
  socket = builtins.mapAttrs (_: key: {
    socket.key = key;
  }) notnft.socketKeys;
  rt = (builtins.mapAttrs (_: key: {
    rt.key = key;
  }) notnft.rtKeys) // (lib.genAttrs [ "ip" "ip6" ] (family:
    builtins.mapAttrs (_: key: {
      rt = { inherit key family; };
    }) notnft.rtKeys));
  osf = (builtins.mapAttrs (_: key: {
    osf.key = key;
  }) notnft.osfKeys) // (let ttl = builtins.mapAttrs (_: ttl: builtins.mapAttrs (_: key: {
    osf = { inherit ttl key; };
  }) notnft.osfKeys) notnft.osfTtls; in ttl // { inherit ttl; });
  ipsec = lib.genAttrs [ "in" "out" ] (dir': let dir = notnft.ipsecDirs.${dir'}; in (builtins.mapAttrs (_: key: {
    __expr__.ipsec = { inherit key dir; };
    __functor = self: attrs: self.__expr__ // {
      ipsec = self.__expr__.ipsec // attrs;
    };
  }) (lib.filterAttrs (k: v: !(v.needsFamily or false)) notnft.ipsecKeys)) // (lib.genAttrs [ "ip" "ip6" ] (family: builtins.mapAttrs (_: key: {
    __expr__.ipsec = { inherit key dir family; };
    __functor = self: attrs: self.__expr__ // {
      ipsec = self.__expr__.ipsec // attrs;
    };
  }) (lib.filterAttrs (k: v: v.needsFamily or false) notnft.ipsecKeys))));
  accept = { accept = null; };
  drop = { drop = null; };
  continue = { continue = null; };
  return = { return = null; };
  jump = target: { jump.target = target; };
  goto = target: { goto.target = target; };
  range = a: b: { range = [ a b ]; };
  fib = flags': result':
    let
      flags = fillEnum notnft.fibFlags flags';
      result = fillEnum notnft.fibResults result';
    in
      { fib = { inherit flags result; }; };
  # anonymous set
  set = {
    # set statement
    add = set: elem: { set = { op = notnft.setOps.add; inherit set elem; }; };
    update = set: elem: { set = { op = notnft.setOps.update; inherit set elem; }; };
    delete = set: elem: { set = { op = notnft.setOps.delete; inherit set elem; }; };
    # set expr
    __functor = self: x: { set = x; };
  };
  map = {
    __object__ = "map";
    __functor = self: key: data: {
      map = {
        inherit key;
        data = if builtins.isList data then data else lib.mapAttrsToList (k: v: [ k v ]) data;
      };
    };
  };
  limit = {
    __object__ = "limit";
    __functor = self: attrs: { limit = fillEnums { per = notnft.timeUnits; } attrs; };
  };
  fwd = attrs: { fwd = fillEnums { family = notnft.ipFamilies; } attrs; };
  notrack = {
    notrack = null;
  };
  dup = attrs: { dup = attrs; };
  cidr = addr: len: { prefix = { inherit addr len; }; };
  snat = x:
    let
      fill = fillEnums { flags = notnft.natFlags; type_flags = notnft.natTypeFlags; family = notnft.ipFamilies; };
    in if builtins.isAttrs x then {
      snat = fill x;
    } else {
      __expr__.snat.addr = x;
      __functor = self: attrs:
        if builtins.isInt attrs then {
          __expr__.snat = self.__expr__.snat // { port = attrs; };
          __functor = self: attrs: { snat = self.__expr__.snat // fill attrs; };
        } else { snat = self.__expr__.snat // fill attrs; };
    };
  dnat = x:
    let
      fill = fillEnums { flags = notnft.natFlags; type_flags = notnft.natTypeFlags; family = notnft.ipFamilies; };
    in if builtins.isAttrs x then {
      dnat = fill x;
    } else {
      __expr__.dnat.addr = x;
      __functor = self: attrs:
        if builtins.isInt attrs then {
          __expr__.dnat = self.__expr__.dnat // { port = attrs; };
          __functor = self: attrs: { dnat = self.__expr__.dnat // fill attrs; };
        } else { dnat = self.__expr__.dnat // fill attrs; };
    };
  masquerade =
    let
      fill = fillEnums { flags = notnft.natFlags; type_flags = notnft.natTypeFlags; };
    in {
      __expr__.masquerade = { };
      __functor = self: x: if builtins.isInt x then {
        __expr__.masquerade.port = x;
        __functor = self: attrs: { masquerade = self.__expr__.masquerade // fill attrs; };
      } else {
        masquerade = fill x;
      };
    };
  redirect =
    let
      fill = fillEnums { flags = notnft.natFlags; type_flags = notnft.natTypeFlags; };
    in {
      __expr__.redirect = { };
      __functor = self: x: if builtins.isInt x then {
        __expr__.redirect.port = x;
        __functor = self: attrs: { redirect = self.__expr__.redirect // fill attrs; };
      } else {
        redirect = fill x;
      };
    };
  reject = {
    __expr__.reject = { };
    __functor = self: attrs:  {
      reject = self.__expr__.reject // fillEnums { type = notnft.rejectTypes; } attrs;
    };
  };
  vmap = key: data: {
    vmap = {
      inherit key;
      data = if builtins.isList data then data else lib.mapAttrsToList (k: v: [ k v ]) data;
    };
  };
  elem = attrs:
    if attrs?val || attrs?timeout || attrs?expires || attrs?comment then
      (if attrs?val then {
        elem = attrs;
      } else val: {
        elem = attrs // { inherit val; };
      })
    else attrs': {
      elem = (attrs' // { val = attrs; });
    };
  mangle = key: value: { mangle = {
    inherit key;
    value = fillEnum (notnft.exprEnumsMerged key) value;
  }; };
  concat = exprs: {
    __expr__.concat = lib.toList exprs;
    __functor = self: x: self // {
      __expr__.concat = self.__expr__.concat ++ lib.toList x;
    };
  };
  counter = {
    __expr__.counter = { };
    __functor = self: attrs: { counter = attrs; };
  };
  quota = {
    __object__ = "quota";
    __functor = self: attrs: {
      quota = fillEnums { val_unit = notnft.byteUnits; used_unit = notnft.byteUnits; } attrs;
    };
  };
  log = attrs: {
    log = fillEnums { level = notnft.logLevels; flags = notnft.logFlags; } attrs;
  };
  # ct helper set
  ctHelper = {
    __object__ = "ct helper";
    __functor = self: expr: { "ct helper" = expr; };
  };
  meter = attrs: { meter = attrs; };
  ctCount = attrs: { "ct count" = if builtins.isInt attrs then { val = attrs; } else attrs; };
  ctTimeout = {
    __object__ = "ct timeout";
    __functor = self: attrs: { "ct timeout" = attrs; };
  };
  ctExpectation = {
    __object__ = "ct expectation";
    __functor = self: attrs: { "ct expectation" = attrs; };
  };
  xt = attrs: { xt = attrs; };
  flow.add = name: {
    flow = {
      op = notnft.flowtableOps.add;
      inherit name;
    };
  };
  queue = {
    __expr__ = { queue = { }; };
    __functor = self: attrs: {
      queue = fillEnums { flags = notnft.queueFlags; } attrs;
    };
  };
  tproxy = attrs: {
    tproxy = fillEnums { family = notnft.ipFamilies; } attrs;
  };
  synproxy = {
    __object__ = "synproxy";
    __functor = self: attrs: {
      synproxy = fillEnums { flags = notnft.synproxyFlags; } attrs;
    };
  };
  # reset tcp option
  reset = opt:
    if opt?__object__ then mkCmd "reset" opt else {
      reset = opt;
    };
  dccpOpt = type: {
    "dccp option" = { inherit type; };
  };
  # set secmark or whatever?
  secmark = {
    __object__ = "secmark";
    __functor = self: secmark: { inherit secmark; };
  };
  inherit (notnft) exists missing;
  compileStmt = fixupStmts;
  compileExpr = fixupStmts;
  compileCmd = finalize { };
  compile = x: if x?__fixup then compileCmd x else fixupStmts x;
}; in self

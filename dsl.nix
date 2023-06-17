# disable convenience functors in test to allow serializing intermediate state to json
{ lib, notnft }:

let
  toList = x: lib.toList
    (if builtins.isAttrs x && x?__list__ then x.__list__
    else if builtins.isAttrs x then builtins.removeAttrs x [ "__functor" ]
    else x);
  # yes, recursion, too lazy to throw
  # essentially recursion means not enough info is being passed somehow
  passInfo = x: info:
    let info' = info // { __args__ = true; }; in
    if builtins.isFunction x then passInfo (x info') info' else toList x;
  special = x: { __special__ = true; } // x;
  isSpecial = x: x.__special__ or x?__functor;
  isArgs = x: x.__args__ or (builtins.isAttrs x && (x?name || x?comment || x?type || x?hook || x?dev || x?prio || x?policy));
  args = x: builtins.removeAttrs x [ "__args__" ];
  passNamesAnd = attrs: obj:
    if builtins.isAttrs obj && !(isSpecial obj)
    then builtins.concatLists (lib.mapAttrsToList (k: v: passInfo v (attrs // { name = k; })) obj)
    else passInfo obj attrs;
  passNames = passNamesAnd {};
  takeArgs' = added: self: attrs: x:
    (if isArgs x then builtins.foldl' lib.id (self ((args x) // attrs)) added
    else takeArgs' (added ++ [x]) self attrs);
  takeArgs = takeArgs' [];
  fixupStmts = stmts:
    if builtins.isList stmts then map fixupStmts stmts
    else if !(builtins.isAttrs stmts) then stmts
    else if stmts?__expr__ then fixupStmts stmts.__expr__
    else if builtins.any (lib.hasPrefix "_") (builtins.attrNames stmts) then stmts
    else builtins.mapAttrs (k: fixupStmts) stmts;
self = rec {
  # this DSL works by returning attrsets if all info is known, and functions if they expect more attrs
  # compile just extracts the list from the dsl
  compile = x: toList x;
  Ruleset = x: { nftables = passNames x; };
  Table = { family ? null, name ? null, existing ? false } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?name || !attrs?family then takeArgs Table attrs
    else special {
      __list__ = if existing then [] else [ { add.table = builtins.removeAttrs attrs [ "existing" ]; } ];
      __functor = self: obj:
        self // {
          __list__ = self.__list__ ++ (passNamesAnd { table = name; inherit family; } obj);
        };
    };
  ExistingTable = Table { existing = true; };
  Chain' = {
    family ? null
    , table ? null
    , name ? null
    , type ? null
    , hook ? null
    , prio ? null
    , dev ? null
    , policy ? null
    , existing ? false
    # insert (prepend) rules instead of adding (append)
    , prepend ? false
  } @ attrs': 
    let attrs = attrs' // (if builtins.isFunction family then {
      family = family notnft.families;
    } else {}) // (if builtins.isFunction type then {
      type = type notnft.chainTypes;
    } else {}) // (if builtins.isFunction hook then {
      hook = hook notnft.hooks;
    } else {}) // (if builtins.isFunction policy then {
      policy = policy notnft.chainPolicies;
    } else {}) // (if builtins.isFunction prio && attrs'?family then {
      prio = prio (builtins.mapAttrs (k: v: v.value (toString family))
        (lib.filterAttrs (k: v: (!v?families || builtins.elem (toString family) v.families) && (!v?hooks || builtins.elem (toString hook) v.hooks)) notnft.priorities));
    } else {}); in
    if !attrs?name || !attrs?family || !attrs?table then takeArgs Chain' attrs
    else {
      __list__ = if existing then [ ] else [ { add.chain = builtins.removeAttrs attrs [ "prepend" "existing" ]; } ];
      __functor = self: obj:
        if builtins.isList obj && obj != [] && builtins.isList (builtins.head obj) then builtins.foldl' lib.id self obj
        else self // {
          __list__ =
            let
              obj' =
                if builtins.isList obj
                then builtins.foldl' lib.id (Rule' { chain = name; inherit family table prepend; }) obj
                else obj;
              obj'' = toList (passInfo obj' { chain = name; inherit family table; });
            in
              if prepend && existing then obj'' ++ self.__list__
              else if prepend then [ (builtins.head self.__list__) ] ++ obj'' ++ builtins.tail self.__list__
              else self.__list__ ++ obj'';
        };
    };
  Chain = Chain' { };
  ExistingChain = Chain' { existing = true; };
  InsertExistingChain = Chain' { existing = true; insert = true; };
  Rule' = {
    family ? null
    , table ? null
    , chain ? null
    , comment ? null
    , prepend ? false
  } @ attrs': 
    let
      attrs = if builtins.isFunction family then attrs' // {
        family = family notnft.families;
      } else attrs';
      cmd = if prepend then "insert" else "add";
    in
    if !attrs?chain || !attrs?family || !attrs?table then takeArgs Rule' attrs
    else {
      ${cmd}.rule = builtins.removeAttrs attrs [ "prepend" ];
      __functor = self: obj:
        self // {
          ${cmd}.rule = self.${cmd}.rule // {
            expr = (self.${cmd}.rule.expr or []) ++ (toList (fixupStmts obj));
          };
        };
      };
  Rule = Rule' {};
  InsertRule = Rule' { insert = true; };
  Set = {
    family ? null
    , table ? null
    , name ? null
    , handle ? null
    , type ? null
    , policy ? null
    , flags ? null
    , timeout ? null
    , gc-interval ? null
    , size ? null
  } @ attrs':
    let
      attrs = attrs' // (if builtins.isFunction family then {
        family = family notnft.families;
      } else {}) // (if builtins.isFunction policy then {
        policy = policy notnft.setPolicies;
      } else {}) // (if builtins.isFunction type then {
        type = type notnft.nftTypes;
      } else {}) // (if builtins.isFunction flags then {
        flags = flags notnft.setFlags;
      } else {});
      types' = builtins.toList type;
      typeStrs = map toString types';
      enums = builtins.filter (x: x != null) (map (x: notnft.nftType.${x}.enum or null) typeStrs);
      enum = notnft.mergeEnums enums;
    in
    if !attrs?name || !attrs?family || !attrs?table then takeArgs Set attrs
    else {
      add.set = attrs;
      __functor = self: obj':
        let obj = if builtins.isFunction obj' then obj' enum else obj'; in self // {
          add.set = self.add.set // {
            elem = (self.add.set.elem or []) ++ (toList obj);
          };
        };
    };
  Map = {
    family ? null
    , table ? null
    , name ? null
    , handle ? null
    , type ? null
    , map ? null
    , policy ? null
    , flags ? null
    , timeout ? null
    , gc-interval ? null
    , size ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?name || !attrs?family || !attrs?table then takeArgs map attrs
    else {
      add.map = attrs;
      __functor = self: obj:
        if builtins.isList obj && (
              builtins.length obj != 2
              || !(builtins.isList (builtins.head obj))
              || (builtins.length (builtins.head obj)) != 2) then builtins.foldl' lib.id self obj
        else self // {
          add.set = self.add.set // {
            elem = (self.add.set.elem or []) ++ (toList obj);
          };
        };
      };
  Flowtable = {
    family ? null
    , table ? null
    , name ? null
    , hook ? null
    , prio ? null
    , dev ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs Flowtable attrs
    else special { add.flowtable = attrs; };
  Counter = {
    family ? null
    , table ? null
    , name ? null
    , packets ? null
    , bytes ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs Counter attrs
    else special { add.counter = attrs; };
  Quota = {
    family ? null
    , table ? null
    , name ? null
    , bytes ? null
    , used ? null
    , inv ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs Quota attrs
    else special { add.quota = attrs; };
  "Ct helper" = {
    family ? null
    , table ? null
    , name ? null
    , type ? null
    , protocol ? null
    , l3proto ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs self."Ct helper" attrs
    else special { add."ct helper" = attrs; };
  CtHelper = self."Ct helper";
  Limit = {
    family ? null
    , table ? null
    , name ? null
    , rate ? null
    , per ? null
    , burst ? null
    , unit ? null
    , inv ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs Limit attrs
    else special { add.limit = attrs; };
  "Ct timeout" = {
    family ? null
    , table ? null
    , name ? null
    , protocol ? null
    , state ? null
    , value ? null
    , l3proto ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs self."Ct timeout" attrs
    else special { add."ct timeout" = attrs; };
  CtTimeout = self."Ct timeout";
  "Ct expectation" = {
    family ? null
    , table ? null
    , name ? null
    , l3proto ? null
    , protocol ? null
    , dport ? null
    , timeout ? null
    , size ? null
  } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?family || !attrs?table || !attrs?name then takeArgs self."Ct expectation" attrs
    else special { add."ct expectation" = attrs; };
  CtExpectation = self."Ct expectation";
  match = builtins.mapAttrs (_: op: left: right: {
    match = {
      inherit op left;
      right =
        if builtins.isFunction right
        then right (notnft.exprEnumsMerged left)
        else right;
    };
  }) notnft.operators;
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
      __expr__.${op} = [ a (if builtins.isFunction b then b (notnft.exprEnumsMerged a) else b) ];
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
  fib =
    flags':
      let
        flags = if builtins.isFunction flags' then flags' notnft.fibFlags else flags';
      in result':
        let result = if builtins.isFunction result' then result' notnft.fibResults else result'; in
        { fib = { inherit flags result; }; };
  # anonymous set
  set = {
    add = set: elem: { set = { op = notnft.setOps.add; inherit set elem; }; };
    update = set: elem: { set = { op = notnft.setOps.update; inherit set elem; }; };
    delete = set: elem: { set = { op = notnft.setOps.delete; inherit set elem; }; };
    __functor = self: x: { set = x; };
  };
  map = key: data: {
    map = {
      inherit key;
      data = if builtins.isList data then data else lib.mapAttrsToList (k: v: [ k v ]) data;
    };
  };
  limit = attrs @ { per ? null, ... }: {
    limit = attrs
      // (if builtins.isFunction per then { per = per notnft.timeUnits; } else {});
  };
  fwd = { family ? null, ... } @ attrs: {
    fwd = attrs
      // (if builtins.isFunction family then { family = family notnft.ipFamilies; } else { });
  };
  notrack = {
    notrack = null;
  };
  dup = attrs: { dup = attrs; };
  cidr = addr: len: { prefix = { inherit addr len; }; };
  # TODO: pass flags and type_flags if closure
  snat = x: if builtins.isAttrs x then { snat = x; } else {
    __expr__.snat.addr = x;
    __functor = self: attrs: { snat = { addr = x; } // attrs; };
  };
  dnat = x: if builtins.isAttrs x then { dnat = x; } else {
    __expr__.dnat.addr = x;
    __functor = self: attrs: { dnat = { addr = x; } // attrs; };
  };
  masquerade = {
    __expr__.masquerade = { };
    __functor = self: attrs: {
      masquerade = self.__expr__.masquerade // attrs;
    };
  };
  redirect = {
    __expr__.redirect = { };
    __functor = self: attrs: {
      masquerade = self.__expr__.redirect // attrs;
    };
  };
  reject = {
    __expr__.reject = { };
    __functor = self: { type ? null, ... }:  {
      reject = self.__expr__.reject
        // (if builtins.isFunction type then { type = type notnft.rejectTypes; } else { });
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
    value = if builtins.isFunction value then value (notnft.exprEnumsMerged key) else value;
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
  quota = { val_unit ? null, used_unit ? null, ... } @ attrs: {
    quota = attrs
      // (if builtins.isFunction val_unit then { val_unit = val_unit notnft.byteUnits; } else { })
      // (if builtins.isFunction used_unit then { used_unit = used_unit notnft.byteUnits; } else { });
  };
  log = { level ? null, flags ? null, ... }@ attrs: {
    log = attrs
      // (if builtins.isFunction level then { level = level notnft.logLevels; } else { })
      // (if builtins.isFunction flags then { flags = flags notnft.logFlags; } else { });
  };
  # ct helper set
  ctHelper = expr: { "ct helper" = expr; };
  meter = attrs: { meter = attrs; };
  ctCount = attrs: { "ct count" = if builtins.isInt attrs then { val = attrs; } else attrs; };
  ctTimeout = attrs: { "ct timeout" = attrs; };
  ctExpectation = attrs: { "ct expectation" = attrs; };
  xt = attrs: { xt = attrs; };
  flow.add = name: {
    flow = {
      op = notnft.flowtableOps.add;
      inherit name;
    };
  };
  queue = {
    __expr__ = { queue = { }; };
    __functor = self: { flags ? null, ... } @ attrs: {
      queue = attrs
        // (if builtins.isFunction flags then { flags = flags notnft.queueFlags; } else { });
    };
  };
  tproxy = { family ? null, ... } @ attrs: {
    tproxy = attrs //
      (if builtins.isFunction family then { family = family notnft.ipFamilies; } else { });
  };
  synproxy = { flags ? null, ... } @ attrs: {
    synproxy = attrs //
      (if builtins.isFunction flags then { flags = flags notnft.synproxyFlags; } else { });
  };
  # reset tcp option
  reset = opt: {
    reset = opt;
  };
  # set secmark or whatever?
  secmark = secmark: { inherit secmark; };
  inherit (notnft) exists missing;
}; in self

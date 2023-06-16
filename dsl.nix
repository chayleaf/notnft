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
    else if stmts?__expr__ then stmts.__expr__
    else if builtins.any (lib.hasPrefix "_") (builtins.attrNames stmts) then stmts
    else builtins.mapAttrs (k: fixupStmts) stmts;
self = rec {
  # this DSL works by returning attrsets if all info is known, and functions if they expect more attrs
  # compile just extracts the list from the dsl
  compile = x: toList x;
  Ruleset = x: { nftables = passNames x; };
  Table = { family ? null, name ? null } @ attrs':
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?name || !attrs?family then takeArgs Table attrs
    else special {
      __list__ = [ { add.table = attrs; } ];
      __functor = self: obj:
        self // {
          __list__ = self.__list__ ++ (passNamesAnd { table = name; inherit family; } obj);
        };
    };
  Chain' = {
    family ? null
    , table ? null
    , name ? null
    , type ? null
    , hook ? null
    , prio ? null
    , dev ? null
    , policy ? null
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
      __list__ = [ { add.chain = attrs; } ];
      __functor = self: obj:
        if builtins.isList obj && obj != [] && builtins.isList (builtins.head obj) then builtins.foldl' lib.id self obj
        else self // {
          __list__ =
            let obj' =
              if builtins.isList obj
              then builtins.foldl' lib.id (Rule' { chain = name; inherit family table; }) obj
              else obj;
            in self.__list__ ++ (passInfo obj' { chain = name; inherit family table; });
        };
    };
  Chain = Chain' {};
  Rule' = {
    family ? null
    , table ? null
    , chain ? null
    , comment ? null
  } @ attrs': 
    let attrs = if builtins.isFunction family then attrs' // {
      family = family notnft.families;
    } else attrs'; in
    if !attrs?chain || !attrs?family || !attrs?table then takeArgs Rule' attrs
    else {
      add.rule = attrs; 
      __functor = self: obj:
        self // {
          add.rule = self.add.rule // {
            expr = (self.add.rule.expr or []) ++ (toList (fixupStmts obj));
          };
        };
      };
  Rule = Rule' {};
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
        then right (lib.traceVal (notnft.exprEnumsMerged left))
        else right;
    };
  }) notnft.operators;
  is = match;
  ct = builtins.mapAttrs (_: key: {
    __expr__.ct.key = key;
    __functor = self: attrs: {
      ct = self.ct // attrs;
    };
  }) notnft.ctKeys;
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
    op = lib.genAttrs [ "|" "^" "&" "<<" ">>" ] (op: a:
      if builtins.isList a && builtins.length a >= 2 then builtins.foldl' (a: b: {
        ${op} = [ a (if builtins.isFunction b then b (notnft.exprEnumsMerged a) else b) ];
      }) (builtins.head a) (builtins.tail a)
      else b: {
        ${op} = [ a (if builtins.isFunction b then b (notnft.exprEnumsMerged a) else b) ];
      });
  meta = builtins.mapAttrs (_: key: {
    meta.key = key;
  }) notnft.metaKeys;
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
  set = x: { set = x; };
  limit = attrs @ { per ? null, ... }: {
    limit = attrs // (if builtins.isFunction per then {
      per = per notnft.timeUnits;
    } else {});
  };
  cidr = addr: len: { prefix = { inherit addr len; }; };
  masquerade = {
    __expr__.masquerade = { };
    __functor = self: attrs: {
      masquerade = self.masquerade // attrs;
    };
  };
  vmap = key: data: {
    vmap = {
      inherit key;
      data = if builtins.isList data then data else lib.mapAttrsToList (k: v: [ k v ]) data;
    };
  };
  mangle = key: value: { mangle = { inherit key value; }; };
  inherit (notnft) exists missing;
}; in self

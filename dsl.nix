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
self = rec {
  # this DSL works by returning attrsets if all info is known, and functions if they expect more attrs
  # compile just extracts the list from the dsl
  compile = x: toList x;
  ruleset = x: { nftables = passNames x; };
  table = { family ? null, name ? null } @ attrs:
    if !attrs?name || !attrs?family then takeArgs table attrs
    else special {
      __list__ = [ { add.table = attrs; } ];
      __functor = self: obj:
        self // {
          __list__ = self.__list__ ++ (passNamesAnd { table = name; inherit family; } obj);
        };
    };
  chain' = {
    family ? null
    , table ? null
    , name ? null
    , type ? null
    , hook ? null
    , prio ? null
    , dev ? null
    , policy ? null
  } @ attrs: 
    if !attrs?name || !attrs?family || !attrs?table then takeArgs chain' attrs
    else {
      __list__ = [ { add.chain = attrs; } ];
      __functor = self: obj:
        if builtins.isList obj && obj != [] && builtins.isList (builtins.head obj) then builtins.foldl' lib.id self obj
        else self // {
          __list__ =
            let obj' =
              if builtins.isList obj
              then builtins.foldl' lib.id (rule' { chain = name; inherit family table; }) obj
              else obj;
            in self.__list__ ++ (passInfo obj' { chain = name; inherit family table; });
        };
    };
  chain = chain' {};
  rule' = {
    family ? null
    , table ? null
    , chain ? null
    , comment ? null
  } @ attrs: 
    if !attrs?chain || !attrs?family || !attrs?table then takeArgs rule' attrs
    else {
      add.rule = attrs; 
      __functor = self: obj:
        self // {
          add.rule = self.add.rule // {
            expr = (self.add.rule.expr or []) ++ (toList obj);
          };
        };
      };
  rule = rule' {};
  set = {
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
  } @ attrs:
    if !attrs?name || !attrs?family || !attrs?table then takeArgs set attrs
    else {
      add.set = attrs;
      __functor = self: obj:
        self // {
          add.set = self.add.set // {
            elem = (self.add.set.elem or []) ++ (toList obj);
          };
        };
    };
  map = {
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
  } @ attrs:
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
  flowtable = {
    family ? null
    , table ? null
    , name ? null
    , hook ? null
    , prio ? null
    , dev ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs flowtable attrs
    else special { add.flowtable = attrs; };
  counter = {
    family ? null
    , table ? null
    , name ? null
    , packets ? null
    , bytes ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs counter attrs
    else special { add.counter = attrs; };
  quota = {
    family ? null
    , table ? null
    , name ? null
    , bytes ? null
    , used ? null
    , inv ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs quota attrs
    else special { add.quota = attrs; };
  "ct helper" = {
    family ? null
    , table ? null
    , name ? null
    , type ? null
    , protocol ? null
    , l3proto ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs self."ct helper" attrs
    else special { add."ct helper" = attrs; };
  limit = {
    family ? null
    , table ? null
    , name ? null
    , rate ? null
    , per ? null
    , burst ? null
    , unit ? null
    , inv ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs limit attrs
    else special { add.limit = attrs; };
  "ct timeout" = {
    family ? null
    , table ? null
    , name ? null
    , protocol ? null
    , state ? null
    , value ? null
    , l3proto ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs self."ct timeout" attrs
    else special { add."ct timeout" = attrs; };
  "ct expectation" = {
    family ? null
    , table ? null
    , name ? null
    , l3proto ? null
    , protocol ? null
    , dport ? null
    , timeout ? null
    , size ? null
  } @ attrs: 
    if !attrs?family || !attrs?table || !attrs?name then takeArgs self."ct expectation" attrs
    else special { add."ct expectation" = attrs; };
  match = builtins.mapAttrs (_: op: left: right: {
    match = {
      inherit op left right;
    };
  }) notnft.operators;
  is = match;
  ct = builtins.mapAttrs (_: key: {
    ct.key = key;
  }) notnft.ctKeys;
  ct' = builtins.mapAttrs (_: key: { family ? null, dir ? null } @ attrs: {
    ct = {
      inherit key;
    } // attrs;
  }) notnft.ctKeys;
  payload = builtins.mapAttrs
    (_: proto:
      (builtins.listToAttrs (builtins.map (field: {
        name = field;
        value.payload = {
          protocol = proto;
          field = notnft.payloadFields.${field};
        };
      }) proto.__info__.fields)))
    notnft.payloadProtocols;
  tcpOpt = builtins.mapAttrs
    (_: opt:
      (builtins.listToAttrs (builtins.map (field: {
        name = field;
        value."tcp option" = {
          name = opt;
          field = notnft.tcpOptionFields.${field};
        };
      }) opt.__info__.fields)) // {
        __expr__."tcp option".name = opt;
      })
    notnft.tcpOptions;
    op = lib.genAttrs [ "|" "^" "&" "<<" ">>" ] (op: a:
      if builtins.isList a && builtins.length a >= 2 then builtins.foldl' (old: new: {
        ${op} = [ old new ];
      }) (builtins.head a) (builtins.tail a)
      else b: {
    ${op} = [ a b ];
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
  fib = flags: result: { fib = { inherit flags result; }; };
  # anonymous set
  set' = x: { set = x; };
  limit' = x: { limit = x; };
  cidr = addr: len: { prefix = { inherit addr len; }; };
  masquerade = { masquerade = {}; };
  masquerade' = attrs: { masquerade = attrs; };
  vmap = key: data: {
    vmap = {
      inherit key;
      data = if builtins.isList data then data else lib.mapAttrsToList (k: v: [ k v ]) data;
    };
  };
  mangle = key: value: { mangle = { inherit key value; }; };
}; in self

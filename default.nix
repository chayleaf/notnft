{ lib
, config ? {}
, ... }:

let
  cfg = config.notnft or {};
  enumMode = cfg.enumMode or "normal";
  laxEnums = enumMode == "lax";
  strictEnums = enumMode == "strict";
  CTX_F_RHS = 1;
  CTX_F_STMT = 2;
  CTX_F_PRIMARY = 4;
  # CTX_F_DTYPE = 8;
  CTX_F_SET_RHS = 16;
  CTX_F_MANGLE = 32;
  CTX_F_SES = 64; # set_elem_expr_stmt
  CTX_F_MAP = 128; # LHS of map_expr
  CTX_F_CONCAT = 256;
  CTX_F_ALL = 1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 + 256;
  isImmediateExpr = expr: builtins.isInt expr || builtins.isString expr || builtins.isPath expr || builtins.isBool expr;
  # this assumes the structure is already checked, it just checks whether the expressions make sense in this context
  isValidExpr = ctx: expr:
    let
      hasAllBits = bits: x: builtins.bitAnd bits x == bits;
      isValid = isValidExpr ctx;
      isValidPrim = isValidExpr (builtins.bitOr CTX_F_PRIMARY ctx);
      isValidLhs = isValidExpr (builtins.bitOr CTX_F_MAP ctx);
      isValidRhs = isValidExpr (builtins.bitOr CTX_F_RHS ctx);
      isValidSetRhs = isValidExpr (builtins.bitOr CTX_F_SET_RHS ctx);
      isValidCat = isValidExpr (builtins.bitOr CTX_F_CONCAT ctx);
    in
      if builtins.isInt expr || builtins.isString expr || builtins.isPath expr then true
      else if builtins.isBool expr then (hasAllBits CTX_F_RHS ctx) != 0 || (hasAllBits CTX_F_PRIMARY ctx) != 0
      else if builtins.isList expr then (
        if hasAllBits CTX_F_PRIMARY ctx then false
        else if hasAllBits CTX_F_RHS ctx || hasAllBits CTX_F_STMT ctx then builtins.all isValid expr
        else false)
      else if !(builtins.isAttrs expr) then false
      else if builtins.length (builtins.attrNames expr) != 1 then false
      # extracted from src/parser_json.c
      else let
        key = builtins.head (builtins.attrNames expr);
        contexts = builtins.mapAttrs (k: builtins.foldl' builtins.bitOr 0) {
          concat = [ CTX_F_RHS CTX_F_STMT /*CTX_F_DTYPE*/ CTX_F_SET_RHS CTX_F_SES CTX_F_MAP ];
          set = [ CTX_F_RHS CTX_F_STMT ];
          map = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS ];
          prefix = [ CTX_F_RHS CTX_F_SET_RHS CTX_F_STMT CTX_F_CONCAT ];
          range = [ CTX_F_RHS CTX_F_SET_RHS CTX_F_STMT CTX_F_CONCAT ];
          payload = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_MANGLE CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          exthdr = [ CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          "tcp option" = [ CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_MANGLE CTX_F_SES CTX_F_CONCAT ];
          "ip option" = [ CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_MANGLE CTX_F_SES CTX_F_CONCAT ];
          "sctp chunk" = [ CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_MANGLE CTX_F_SES CTX_F_CONCAT ];
          meta = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_MANGLE CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          osf = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_MAP CTX_F_CONCAT ];
          ipsec = [ CTX_F_PRIMARY CTX_F_MAP CTX_F_CONCAT ];
          socket = [ CTX_F_PRIMARY CTX_F_CONCAT ];
          rt = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          ct = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_MANGLE CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          numgen = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          jhash = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          symhash = [ CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          fib = [ CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          "|" = [ CTX_F_RHS CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          "^" = [ CTX_F_RHS CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          "&" = [ CTX_F_RHS CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          ">>" = [ CTX_F_RHS CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          "<<" = [ CTX_F_RHS CTX_F_STMT CTX_F_PRIMARY CTX_F_SET_RHS CTX_F_SES CTX_F_MAP CTX_F_CONCAT ];
          accept = [ CTX_F_RHS CTX_F_SET_RHS ];
          drop = [ CTX_F_RHS CTX_F_SET_RHS ];
          continue = [ CTX_F_RHS CTX_F_SET_RHS ];
          jump = [ CTX_F_RHS CTX_F_SET_RHS ];
          goto = [ CTX_F_RHS CTX_F_SET_RHS ];
          return = [ CTX_F_RHS CTX_F_SET_RHS ];
          elem = [ CTX_F_RHS CTX_F_STMT CTX_F_PRIMARY CTX_F_SES ];
        };
        extraChecks = let
          binOpCheck = expr:
            isValidPrim (builtins.head expr)
            && isValidRhs (builtins.head (builtins.tail expr));
        in {
          jhash = { expr, ... }: isValid expr;
          "|" = binOpCheck;
          "^" = binOpCheck;
          "&" = binOpCheck;
          ">>" = binOpCheck;
          "<<" = binOpCheck;
          concat = builtins.all isValidCat;
          prefix = { addr, ... }: isValidPrim addr;
          range = builtins.all isValidPrim;
          set = expr:
            if builtins.isList expr then builtins.all (elem:
              if builtins.isList elem && builtins.length elem == 2
              then isValidRhs (builtins.head elem) && isValidSetRhs (builtins.head (builtins.tail elem))
              else isValidRhs elem) expr
            else isImmediateExpr expr;
          map = { key, data }: isValidLhs key && isValidRhs data;
          elem = { val, ... }: isValidExpr val;
        };
        in
        hasAllBits ctx (contexts.${key} or CTX_F_ALL)
        && (extraChecks.${key} or (expr: true)) expr.${key};

  # get all expressions contained in an expression (non-recursive)
  # warning: this may not yet be merged
  innerExprs = expr:
    if builtins.isList expr then expr
    else if !(builtins.isAttrs expr) then []
    else if builtins.length (builtins.attrNames expr) != 1 then []
    else if expr?map.key && expr?map.data then [ expr.map.key expr.map.data ]
    else if expr?range.min && expr?range.max then [ expr.range.min expr.range.max ]
    else if expr?"|".left && expr?"|".right then [ expr."|".left expr."|".right ]
    else if expr?"&".left && expr?"&".right then [ expr."&".left expr."&".right ]
    else if expr?"^".left && expr?"^".right then [ expr."^".left expr."^".right ]
    else if expr?"<<".left && expr?"<<".right then [ expr."<<".left expr."<<".right ]
    else if expr?">>".left && expr?">>".right then [ expr.">>".left expr.">>".right ]
    else lib.toList (expr.jhash.expr or expr."|" or expr."&" or expr."^" or expr."<<" or expr.">>" or expr.concat or expr.prefix or expr.range or expr.set or expr.elem.val or []);

  # get the expr plus all of its inner exprs, recursively
  # warning: this may not yet be merged
  innerExprsRec = expr: [ expr ] ++ (map innerExprsRec (innerExprs expr));

  isStringLike = s: builtins.isString s || s?__toString;

  # get all enums appropriate for the expression (might have duplicates), or empty list
  # specifically, this is used when passed a closure in the DSL for RHS of an operation
  # warning: this may not yet be merged
  exprEnums = expr:
    (if builtins.isList expr then builtins.concatMap exprEnums expr
    else if !(builtins.isAttrs expr) then []
    else if expr?__expr__ then exprEnums expr.__expr__
    else if expr?__enumName__ && nftTypes?${expr.__enumName__}.enum then [ nftTypes.${expr.__enumName__}.enum ]
    else if builtins.length (builtins.attrNames expr) != 1 then []
    else let key = builtins.head (builtins.attrNames expr); val = expr.${key}; in {
      # set = exprEnum val;
      map = exprEnums val.key ++ exprEnums val.data;
      # prefix = exprEnum val.addr;
      # range = exprEnum val;
      payload =
        if val?base then [ ]
        else if !(isStringLike (val.protocol or null)) then [ ]
        else if !(isStringLike (val.field or null)) then [ booleans ]
        else if (payloadProtocols?${toString val.protocol}.fields.${toString val.field}.enum) then [ payloadProtocols.${toString val.protocol}.fields.${toString val.field}.enum ]
        else [ ];
      exthdr =
        if !(isStringLike (val.name or null)) then [ ]
        else if !(isStringLike (val.field or null)) then [ booleans ]
        else if exthdrs?${toString val.name}.fields.${toString val.field}.enum then [ exthdrs.${toString val.name}.fields.${toString val.field}.enum ]
        else [ ];
      "tcp option" =
        if val?base then []
        else if !(isStringLike (val.name or null)) then [ ]
        else if !(isStringLike (val.field or null)) then [ booleans ]
        else if tcpOptions?${toString val.name}.fields.${toString val.field}.enum then [ tcpOptions.${toString val.name}.fields.${toString val.field}.enum ]
        else [ ];
      "ip option" =
        if !(isStringLike (val.name or null)) then [ ]
        else if !(isStringLike (val.field or null)) then [ booleans ]
        else if ipOptions?${toString val.name}.fields.${toString val.field}.enum then [ ipOptions.${toString val.name}.fields.${toString val.field}.enum ]
        else [ ];
      "sctp chunk" =
        if !(isStringLike (val.name or null)) then [ ]
        else if !(isStringLike (val.field or null)) then [ booleans ]
        else if sctpChunks?${toString val.name}.fields.${toString val.field}.enum then [ sctpChunks.${toString val.name}.fields.${toString val.field}.enum ]
        else [ ];
      meta =
        if isStringLike (val.key or null) && metaKeys?${toString val.key}.type.enum then [ metaKeys.${toString val.key}.type.enum ]
        else [ ];
      # osf = [ ]; returns a string
      # ipsec = [ ]; returns int/ipv4/ipv6 depending on params
      # can return other stuff too
      socket =
        if isStringLike (val.key or null) && (toString val.key == "transparent" || toString val.key == "wildcard") then [ booleans ]
        else [ ];
      # returns realm/ipv4/ipv6/int/bool
      rt = if isStringLike (val.key or null) && toString val.key == "ipsec" then [ booleans ] else [ ];
      ct = if isStringLike (val.key or null) then lib.toList ({
        state = ctStates;
        direction = ctDirs;
        status = ctStatuses;
        l3proto = nfProtos;
      }.${toString val.key} or []) else [ ];
      # numgen = [ ];
      # jhash = [ ];
      # symhash = [ ];
      fib =
        if isStringLike (val.result or null)
        then lib.toList ({ type = fibAddrTypes; }.${toString val.result} or [])
        else [ ];
      "|" = exprEnums val;
      "^" = exprEnums val;
      "&" = exprEnums val;
      ">>" = exprEnums val;
      "<<" = exprEnums val;
      elem = val?val && exprEnums val.val;
    }.${key});

  # get all enums appropriate for the expression (might have duplicates), or empty list
  # warning: this may not yet be merged
  exprEnumsRec = expr:
    builtins.concatMap exprEnums (innerExprsRec expr);

  mergeEnums = allEnums:
    lib.filterAttrs (k: v: v != null)
      (builtins.zipAttrsWith
        (name: values:
          if builtins.length values == 1
          then builtins.head values
          # if more than one enum has this value, simply pass the name
          else name)
        (lib.unique allEnums));

  # warning: expr may not yet be merged
  exprEnumsMerged = expr: mergeEnums (exprEnumsRec expr);

  # this is a customized version of lib.types.submodule
  # - advantages:
  #   - a custom merge functions can be applied at the end, for doing some final checks and fixups
  #   - I use null as a placeholder for undefined values. By default nulls are automatically stripped from the merged output,
  #     unless `skipNulls` is `false`
  #   - hence description is much better as it's aware of both nullable and non-nullable options
  #   - a custom chk function can be applied. Also, the default chk function checks that all fields are present
  #     - this is needed for either to function well with nftables' schema, as it only uses `chk` to check whether a type is compatible
  #     - but I don't need `lib.types.either` or `lib.types.oneOf` anyway as I use a custom `oneOf'`...
  # - disadvantages:
  #   - the above means that unlike lib.types.submodule, here you can't define the same submodule in multiple separate files,
  #     the definition must be contained in a single attrset (you can't use functions/nix file paths in place of the attrset either)
  #   - Honestly I'm not sure why you would set a single nftables expr/stmt in multiple different locations, so it should be fine.
  submodule' = { options, finalMerge ? lib.id, skipNulls ? true, freeformType ? null, chk ? null }:
  let
    reqFields = builtins.attrNames (if skipNulls then lib.filterAttrs (k: v: v.type.name != "nullOr") options else options);
    optFields = if skipNulls then builtins.attrNames (lib.filterAttrs (k: v: v.type.name == "nullOr") options) else [];
    reqFieldsDesc =
      if reqFields == [] then null
      else if builtins.length reqFields == 1 then ''field "${builtins.head reqFields}"''
      else "fields ${builtins.concatStringsSep ", " (map (x: ''"${x}"'') reqFields)}";
    optFieldsDesc =
      if optFields == [] then null
      else if builtins.length optFields == 1 then ''optional field "${builtins.head optFields}"''
      else "optional fields ${builtins.concatStringsSep ", " (map (x: ''"${x}"'') optFields)}";
  in
    submoduleWith' {
      shorthandOnlyDefinesConfig = true;
      modules = lib.toList ({
        inherit options;
      } // (if freeformType != null then {
        inherit freeformType;
      } else {}));
      description = "submodule with ${builtins.concatStringsSep " and " (builtins.filter builtins.isString [ reqFieldsDesc optFieldsDesc ])}";
      descriptionClass = "conjunction";
      chk = if chk != null then chk else x: builtins.all (optName: x?${optName}) reqFields;
      inherit finalMerge skipNulls;
    };
  # single-option submodule' (SK = single key)
  submoduleSK = key: val: submodule' {
    skipNulls = false;
    options.${key} = val;
  };
  submoduleWith' =
    { modules
    , specialArgs ? {}
    , shorthandOnlyDefinesConfig ? false
    , description ? null
    , descriptionClass ? "noun"
    , class ? null
    , finalMerge ? lib.id
    , skipNulls ? true
    , chk ? (_: true)
    }@attrs:
    let
      inherit (lib.modules) evalModules;

      allModules = defs: map ({ value, file }:
        if builtins.isAttrs value && shorthandOnlyDefinesConfig
        then { _file = file; config = value; }
        else { _file = file; imports = [ value ]; }
      ) defs;

      base = evalModules {
        inherit class specialArgs;
        modules = [{ _module.args.name = lib.mkOptionDefault "‹name›"; }] ++ modules;
      };

      freeformType = base._module.freeformType;

      name = "submodule'";

    in lib.mkOptionType {
      inherit name descriptionClass;
      description =
        if description != null then description
        else freeformType.description or name;
      check = x: builtins.isAttrs x && chk x;
      merge = loc: defs:
        finalMerge ((if skipNulls then lib.filterAttrs (k: v: !(builtins.isNull v)) else lib.id) (base.extendModules {
          modules = [ { _module.args.name = lib.last loc; } ] ++ allModules defs;
          prefix = loc;
        }).config);
      emptyValue = { value = {}; };
      getSubOptions = prefix: (base.extendModules
        { inherit prefix; }).options // lib.optionalAttrs (freeformType != null) {
          # Expose the sub options of the freeform type. Note that the option
          # discovery doesn't care about the attribute name used here, so this
          # is just to avoid conflicts with potential options from the submodule
          _freeformOptions = freeformType.getSubOptions prefix;
        };
      getSubModules = modules;
      substSubModules = m: submoduleWith' (attrs // {
        modules = m;
      });
      nestedTypes = lib.optionalAttrs (freeformType != null) {
        freeformType = freeformType;
      };
      functor = lib.types.defaultFunctor name // {
        type = submoduleWith';
        payload = {
          inherit modules class specialArgs shorthandOnlyDefinesConfig description;
        };
        binOp = lhs: rhs: {
          class =
            # `or null` was added for backwards compatibility only. `class` is
            # always set in the current version of the module system.
            if lhs.class or null == null then rhs.class or null
            else if rhs.class or null == null then lhs.class or null
            else if lhs.class or null == rhs.class then lhs.class or null
            else throw "A submoduleWith' option is declared multiple times with conflicting class values \"${toString lhs.class}\" and \"${toString rhs.class}\".";
          modules = lhs.modules ++ rhs.modules;
          specialArgs =
            let intersecting = builtins.intersectAttrs lhs.specialArgs rhs.specialArgs;
            in if intersecting == {}
            then lhs.specialArgs // rhs.specialArgs
            else throw "A submoduleWith' option is declared multiple times with the same specialArgs \"${toString (builtins.attrNames intersecting)}\"";
          shorthandOnlyDefinesConfig =
            if lhs.shorthandOnlyDefinesConfig == null
            then rhs.shorthandOnlyDefinesConfig
            else if rhs.shorthandOnlyDefinesConfig == null
            then lhs.shorthandOnlyDefinesConfig
            else if lhs.shorthandOnlyDefinesConfig == rhs.shorthandOnlyDefinesConfig
            then lhs.shorthandOnlyDefinesConfig
            else throw "A submoduleWith' option is declared multiple times with conflicting shorthandOnlyDefinesConfig values";
          description =
            if lhs.description == null
            then rhs.description
            else if rhs.description == null
            then lhs.description
            else if lhs.description == rhs.description
            then lhs.description
            else throw "A submoduleWith' option is declared multiple times with conflicting descriptions";
        };
      };
    };

  # a custom oneOf that doesn't use `builtins.either` and has customized name/description/chk
  # also instead of just calling `chk` when merging, it properly checks whether the values merge with that type via tryEval
  oneOf' = { name, description, descriptionClass ? "noun", types, chk? (_: true) }: lib.types.mkOptionType rec {
    inherit name description descriptionClass;
    check = x: builtins.any (type: type.check x) types && chk x;
    nestedTypes = builtins.listToAttrs (lib.imap0 (i: x: { name = toString i; value = x; }) types);
    typeMerge = null;
    merge = loc: defs:
      let
        validTypes = builtins.filter (type: builtins.all ({ value, ... }: type.check value) defs) types;
        res = builtins.foldl'
                (x: type: if x != null then x else
                  let val = builtins.tryEval (type.merge loc defs);
                  in if val.success then val.value else x)
                null
                validTypes;
      in
        if builtins.length validTypes == 1
          then (builtins.head validTypes).merge loc defs
        else if res == null
          then throw "The definition of option `${lib.showOption loc}` isn't a valid ${description}. Definition values:${lib.options.showDefs defs}"
        else res;
  };

  stringLike = lib.mkOptionType {
    name = "stringLike";
    description = "string";
    descriptionClass = "noun";
    check = s: builtins.isString s || s?__toString;
    merge = loc: defs: toString (lib.options.mergeEqualOption loc defs);
  };

  types =
    # create "name type". Name type is anything that can receive either a name as a literal string or an attrset
    # with the property "name", in which case the property will be taken instead.
    # In hindsight, this might not be a good decision, but I don't see any major downsides either
    # addAt means check for "@" in case of a string, or add "@" before the name in case of name attr
    let mkName = { name, description, addAt ? false }: lib.mkOptionType {
      name = "${name}";
      description = "${description}";
      descriptionClass = "noun";
      check = x: (builtins.isString x && (!addAt || lib.hasPrefix "@" x)) || (builtins.isAttrs x && x?name);
      merge = loc: defs: lib.mergeOneOption loc (map (def@{ value, ... }: def // {
        value =
          if builtins.isAttrs value then (if addAt then "@${value.name}" else value.name)
          else toString value;
      }) defs);
    };
    # create an option with the same attrs as given but make it nullable and default to null
    mkNullOption = attrs: lib.mkOption (attrs // {
      default = null;
      type = lib.types.nullOr attrs.type;
    });
    # this creates an enum type out of an enum (see the other mkEnum function below for a description of what enums are)
    mkEnum = { name, description, enum }: lib.mkOptionType {
      inherit name description;
      descriptionClass = "noun";
      check =
        let chk = x: builtins.isAttrs x && x?__toString && x?__value__ && x?__enumName__ && (builtins.any (y: x.__value__ == y.__value__ && x.__enumName__ == y.__enumName__) (builtins.attrValues enum));
        in if strictEnums then chk
        else if laxEnums then (x: builtins.isString x || (builtins.isAttrs x && x?__toString))
        else (x: builtins.elem x (builtins.attrNames enum) || chk x);
      merge = loc: defs: (lib.mergeOneOption loc (map (def: def // {
        value = toString def.value;
      }) defs));
    };
    mkTableType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = lib.mdDoc ''The table’s family, e.g. **"ip"** or **"ip6"**.'';
        };
        name = {
          type = lib.types.str;
          description = "The table’s name.";
        };
      } // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The table’s handle. In input, it is used only in **delete** command as alternative to **name**.";
        };
      } else { }) // (if withExtraFields then builtins.mapAttrs mkOpt {
        comment = {
          type = lib.types.str;
          description = "Undocumented upstream";
        };
      } else { });
    };
    mkChainType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withNewName ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The chain's name.";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        type = {
          type = types.chainType;
          description = "The chain’s type.";
        };
        hook = {
          type = types.hook;
          description = "The chain’s hook.";
        };
        prio = {
          type = types.chainPriority;
          description = "The chain’s priority.";
        };
        dev = {
          type = lib.types.str;
          description = "The chain’s bound interface (if in the netdev family).";
        };
        policy = {
          type = types.chainPolicy;
          description = "The chain’s policy.";
        };
        comment = {
          type = lib.types.str;
          description = "Undocumented upstream";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The chain’s handle. In input, it is used only in **delete** command as alternative to **name**.";
        };
      } else {})
      // (if withNewName then builtins.mapAttrs mkOpt {
        newname = {
          type = lib.types.str;
          description = lib.mdDoc "A new name for the chain, only relevant in the **rename** command.";
        };
      } else {});
    };
    mkRuleType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withIndex ? false, withExpr ? false, withComment ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        chain = {
          type = types.chainName;
          description = "The chain's name.";
        };
      }
      // (if withExpr then builtins.mapAttrs mkOpt {
        expr = {
          type = lib.types.listOf types.statement;
          description = lib.mdDoc "An array of statements this rule consists of. In input, it is used in **add**/**insert**/**replace** commands only.";
        };
      } else {})
      // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The rule’s handle. In **delete**/**replace** commands, it serves as an identifier of the rule to delete/replace. In **add**/**insert** commands, it serves as an identifier of an existing rule to append/prepend the rule to.";
        };
      } else {})
      // (if withIndex then builtins.mapAttrs mkOpt {
        index = {
          type = lib.types.ints.unsigned;
          description = lib.mdDoc "The rule’s position for add/insert commands. It is used as an alternative to handle then.";
        };
      } else {})
      // (if withComment then builtins.mapAttrs mkOpt {
        comment = {
          type = lib.types.str;
          description = "Optional rule comment.";
        };
      } else {});
    };
    mkSetType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false, isMap ? null }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
      name = if isMap == true then "map" else "set";
    in submodule' {
      finalMerge = ret:
        if ret?elem then
          let expr = ret.elem; in assert lib.assertMsg
            (if builtins.isList expr then builtins.all (elem:
              if builtins.isList elem && builtins.length elem == 2
              then isValidExpr CTX_F_RHS (builtins.head elem) && isValidExpr CTX_F_SET_RHS (builtins.head (builtins.tail elem))
              else isValidExpr CTX_F_RHS elem) expr
            else isImmediateExpr expr)
            "Set/map add command's exprs are invalid in this context";
          finalMerge ret
        else finalMerge ret;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The ${name}'s name.";
        };
      } // (if withExtraFields then builtins.mapAttrs mkOpt {
        type = {
          type = lib.types.either (lib.types.nonEmptyListOf types.keyType) types.keyType;
          description = ''The ${name}’s datatype - might be a string, such as "ipv4_addr" or an array consisting of strings (for concatenated types).'';
        };
      } else {})
      // (if withExtraFields && isMap != false then builtins.mapAttrs mkOpt {
        map = {
          type = types.type;
          description =
            if isMap == true then
              "Type of values this map maps to."
            else
              "Type of values this set maps to (i.e. this set is a map).";
        };
      } else {}) // (if withExtraFields then builtins.mapAttrs mkOpt {
        policy = {
          type = types.setPolicy;
          description = "The ${name}’s policy.";
        };
        flags = {
          type = lib.types.listOf types.setFlag;
          description = "The ${name}’s flags.";
        };
        elem = {
          type =
            if isMap == true then lib.types.nonEmptyListOf (types.listOfSize2 types.expression)
            else lib.types.nonEmptyListOf types.expression;
          description = lib.mdDoc ("Initial ${name} element(s)." + (lib.optionalString (isMap != false) " For mappings, an array of arrays with exactly two elements is expected."));
        };
        timeout = {
          type = lib.types.ints.unsigned;
          description = "Element timeout in seconds.";
        };
        gc-interval = {
          type = lib.types.ints.u32;
          description = "Garbage collector interval in seconds.";
        };
        size = {
          type = lib.types.ints.u32;
          description = "Maximum number of elements supported.";
        };
        stmt = {
          type = lib.types.listOf types.statement;
          description = "Undocumented upstream";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The set’s handle. For input, it is used in the **delete** command only.";
        };
      } else {});
    };
    mkElementType = { finalMerge ? lib.id, reqFields ? [], withElem ? false, isMap ? null }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
      name = if isMap == true then "map" else "set";
    in submodule' {
      finalMerge = ret:
        if ret?elem then
          let expr = ret.elem; in assert lib.assertMsg
            (if builtins.isList expr then builtins.all (elem:
              if builtins.isList elem && builtins.length elem == 2
              then isValidExpr CTX_F_RHS (builtins.head elem) && isValidExpr CTX_F_SET_RHS (builtins.head (builtins.tail elem))
              else isValidExpr CTX_F_RHS elem) expr
            else isImmediateExpr expr)
            "Element add command's exprs are invalid in this context";
          finalMerge ret
        else finalMerge ret;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = lib.mdDoc ''The table’s family, e.g. **"ip"** or **"ip6"**.'';
        };
        table = {
          type = types.tableName;
          description = "The table’s name.";
        };
        name = {
          type = if isMap == true then types.mapName else types.setName;
          description = "The ${name}’s name.";
        };
      } // (if withElem then builtins.mapAttrs mkOpt {
        elem = {
          type =
            if isMap == true then lib.types.nonEmptyListOf (types.listOfSize2 types.expression)
            else lib.types.nonEmptyListOf types.expression;
          description = lib.mdDoc ("Elements to add to the ${name}." + (lib.optionalString (isMap != false) " Use `[ key val ]` to specify a map element."));
        };
      } else {});
    };
    mkFlowtableType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The flowtable's name.";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        hook = {
          type = types.hook;
          description = "The flowtable’s hook.";
        };
        prio = {
          type = types.flowtablePriority;
          description = "The flowtable’s priority.";
        };
        dev = {
          type = lib.types.either (lib.types.nonEmptyListOf lib.types.str) lib.types.str;
          description = "The flowtable’s interface(s).";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The flowtable’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCounterType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The counter's name.";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        packets = {
          type = lib.types.ints.unsigned;
          description = "Packet counter value.";
        };
        bytes = {
          type = lib.types.ints.unsigned;
          description = "Byte counter value.";
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The counter’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkQuotaType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The quota's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        bytes = {
          type = lib.types.ints.unsigned;
          description = "Quota threshold.";
        };
        used = {
          type = lib.types.ints.unsigned;
          description = "Quota used so far.";
        };
        inv = {
          type = lib.types.bool;
          default = false;
          description = "If true, match if the quota has been exceeded.";
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The quota’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkSecmarkType = { finalMerge ? lib.id, reqFields ? [], withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The secmark's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        context = {
          type = lib.types.str;
          description = "Undocumented upstream.";
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {});
    };
    # no handle here!
    mkCtHelperType = { finalMerge ? lib.id, reqFields ? [], withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The ct helper's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        type = {
          type = lib.types.str;
          description = lib.mdDoc ''The ct helper type name, e.g. **"ftp"** or **"tftp"**.'';
        };
        protocol = {
          type = types.ctProto;
          description = "The ct helper’s layer 4 protocol.";
        };
        l3proto = {
          type = types.l3Proto;
          description = lib.mdDoc ''The ct helper's layer 3 protocol, e.g. **"ip"** or **"ip6"**.'';
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {});
    };
    mkLimitType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The limit's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        rate = {
          type = lib.types.ints.unsigned;
          description = "The limit’s rate value.";
        };
        per = {
          type = types.timeUnit;
          description = lib.mdDoc ''Time unit to apply the limit to, e.g. **"week"**, **"day"**, **"hour"**, etc. If omitted, defaults to **"second"**.'';
          defaultText = lib.literalExpression "second";
        };
        rate_unit = {
          type = types.rateUnit;
          description = lib.mdDoc ''Unit of rate values. If omitted, defaults to **"packets"**.'';
          defaultText = lib.literalExpression "packets";
        };
        burst = {
          type = lib.types.ints.u32;
          description = lib.mdDoc "The limit’s burst value. If omitted, defaults to **0**.";
          defaultText = lib.literalExpression 0;
        };
        burst_unit = {
          type = types.rateUnit;
          description = lib.mdDoc ''Unit of burst values. If omitted, defaults to **"bytes"**. Has no effect if `rate_unit` is set to **"packets"**.'';
          defaultText = lib.literalExpression "packets";
        };
        inv = {
          type = lib.types.bool;
          description = lib.mdDoc "If true, match if limit was exceeded. If omitted, defaults to **false**.";
          defaultText = lib.literalExpression false;
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The limit’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCtTimeoutType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The ct timeout object's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        protocol = {
          type = types.ctProto;
          description = "The ct timeout object’s layer 4 protocol.";
        };
        l3proto = {
          type = types.l3Proto;
          description = lib.mdDoc ''The ct timeout object's layer 3 protocol, e.g. **"ip"** or **"ip6"**.'';
        };
        policy = {
          type = lib.types.attrsOf lib.types.ints.u32;
          description = "Undocumented upstream, each key is conn state name (`established`, `syn_sent`, `close_wait`, etc), each val is timeout value";
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The ct timeout object’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCtExpectationType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The ct expectation object's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        l3proto = {
          type = types.l3Proto;
          description = lib.mdDoc ''The ct expectation object's layer 3 protocol, e.g. **"ip"** or **"ip6"**.'';
        };
        protocol = {
          type = types.ctProto;
          description = "The ct expectation object’s layer 4 protocol.";
        };
        dport = {
          type = lib.types.port;
          description = "The destination port of the expected connection.";
        };
        timeout = {
          type = lib.types.ints.u32;
          description = "The time in millisecond that this expectation will live.";
        };
        size = {
          type = lib.types.ints.u8;
          description = "The maximum count of expectations to be living in the same time.";
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The ct expectation object’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkSynproxyType = { finalMerge ? lib.id, reqFields ? [], withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The synproxy's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        mss = {
          type = lib.types.ints.u16;
          description = "Maximum segment size announced to clients.";
        };
        wscale = {
          type = lib.types.ints.u8;
          description = "Window scale announced to clients.";
        };
        flags = {
          type = lib.types.either types.synproxyFlag (lib.types.listOf types.synproxyFlag);
          description = "Optional flags.";
        };
        comment = {
          type = lib.types.str;
          description = "Optional comment.";
        };
      } else {});
    };
  in {
    inherit submodule' submoduleWith' submoduleSK oneOf';
    listOfSize2 = elemType:
      let list = lib.types.addCheck (lib.types.listOf elemType) (l: builtins.length l == 2);
      in list // {
        description = "${lib.types.optionDescriptionPhrase (class: class == "noun") list} of size 2 (key-value pair)";
        emptyValue = { }; # no .value attr, meaning unset
      };
    keyType = mkEnum {
      name = "nftablesKeyType";
      description = "nftables key type";
      enum = lib.filterAttrs (k: v: v.isKey or true) nftTypes;
    };
    type = mkEnum {
      name = "nftablesType";
      description = "nftables type";
      enum = nftTypes;
    };
    family = mkEnum {
      name = "nftablesFamily";
      description = "nftables family";
      enum = families;
    };
    ipFamily = mkEnum {
      name = "nftablesIpFamily";
      description = "nftables ip family";
      enum = ipFamilies;
    };
    chainType = mkEnum {
      name = "nftablesChainType";
      description = "nftables chain type";
      enum = chainTypes;
    };
    chainPolicy = mkEnum {
      name = "nftablesChainPolicy";
      description = "nftables chain policy";
      enum = chainPolicies;
    };
    setPolicy = mkEnum {
      name = "nftablesSetPolicy";
      description = "nftables set policy";
      enum = setPolicies;
    };
    setFlag = mkEnum {
      name = "nftablesSetFlag";
      description = "nftables set flag";
      enum = setFlags;
    };
    natFlag = mkEnum {
      name = "nftablesNatFlag";
      description = "nftables nat flag";
      enum = natFlags;
    };
    natTypeFlag = mkEnum {
      name = "nftablesNatTypeFlag";
      description = "nftables nat type flag";
      enum = natTypeFlags;
    };
    logLevel = mkEnum {
      name = "nftablesLogLevel";
      description = "nftables log level";
      enum = logLevels;
    };
    logFlag = mkEnum {
      name = "nftablesLogFlag";
      description = "nftables log flag";
      enum = logFlags';
    };
    queueFlag = mkEnum {
      name = "nftablesQueueFlag";
      description = "nftables queue flag";
      enum = queueFlags;
    };
    flowtableOp = mkEnum {
      name = "nftablesFlowtableOp";
      description = "nftables flowtable op";
      enum = flowtableOps;
    };
    tableName = mkName {
      name = "nftablesTableName";
      description = "nftables table name";
    };
    chainName = mkName {
      name = "nftablesChainName";
      description = "nftables chain name";
    };
    counterName = mkName {
      name = "nftablesCounterName";
      description = "nftables counter name";
    };
    setName = mkName {
      name = "nftablesSetName";
      description = "nftables set name";
    };
    setReference = mkName {
      name = "nftablesSetReference";
      description = "nftables set reference";
      addAt = true;
    };
    mapName = mkName {
      name = "nftablesMapName";
      description = "nftables map name";
    };
    quotaName = mkName {
      name = "nftablesQuotaName";
      description = "nftables quota name";
    };
    flowtableReference = mkName {
      name = "nftablesFlowtableReference";
      description = "nftables flowtable reference";
      addAt = true;
    };
    hook = mkEnum {
      name = "nftablesHook";
      description = "nftables hook";
      enum = hooks;
    };
    flowtablePriority = lib.mkOptionType {
      name = "nftablesFlowtablePrio";
      description = "nftables flowtable priority";
      descriptionClass = "noun";
      check =
        x:
        builtins.isInt x
        || (if strictEnums then builtins.elem x (builtins.attrValues flowtablePriorities)
            else builtins.elem x (builtins.attrNames flowtablePriorities) || builtins.elem x (builtins.attrValues flowtablePriorities));
      merge = loc: defs: lib.mergeOneOption loc (map (def: def // {
        value = if builtins.isInt def.value then def.value else flowtablePriorities.${toString def.value}.value;
      }) defs);
    };
    chainPriority = lib.mkOptionType {
      name = "nftablesChainPrio";
      description = "nftables chain priority";
      descriptionClass = "noun";
      check =
        x:
        builtins.isInt x
        || (if strictEnums then builtins.elem x (builtins.attrValues chainPriorities)
            else builtins.elem x (builtins.attrNames chainPriorities) || builtins.elem x (builtins.attrValues chainPriorities));
      merge = loc: defs: lib.mergeOneOption loc (map (def: def // {
        value = if builtins.isInt def.value then def.value else toString def.value;
      }) defs);
    };
    ctProto = mkEnum {
      name = "nftablesCtProto";
      description = "nftables ct protocol";
      enum = ctProtocols;
    };
    l3Proto = mkEnum {
      name = "nftablesL3Proto";
      description = "nftables layer 3 protocol";
      enum = l3Families;
    };
    timeUnit = mkEnum {
      name = "nftablesTimeUnit";
      description = "nftables time unit";
      enum = timeUnits;
    };
    byteUnit = mkEnum {
      name = "nftablesByteUnit";
      description = "nftables byte unit";
      enum = byteUnits;
    };
    rateUnit = mkEnum {
      name = "nftablesRateUnit";
      description = "nftables rate unit";
      enum = rateUnits;
    };
    /*connectionState = mkEnum {
      name = "nftablesConnectionState";
      description = "nftables connection state";
      enum = connectionStates;
    };*/
    operator = mkEnum {
      name = "nftablesOperators";
      description = "nftables operator";
      enum = operators';
    };
    rejectType = mkEnum {
      name = "nftablesRejectType";
      description = "nftables reject type";
      enum = rejectTypes';
    };
    setOp = mkEnum {
      name = "nftablesSetOp";
      description = "nftables set op";
      enum = setOps;
    };
    synproxyFlag = mkEnum {
      name = "nftablesSynproxyFlag";
      description = "nftables synproxy flag";
      enum = synproxyFlags;
    };
    xtType = mkEnum {
      name = "nftablesXtType";
      description = "nftables xt type";
      enum = xtTypes;
    };
    payloadBase = mkEnum {
      name = "nftablesPayloadBase";
      description = "nftables payload base";
      enum = payloadBases;
    };
    metaKey = mkEnum {
      name = "nftablesMetaKey";
      description = "nftables meta key";
      enum = metaKeys;
    };
    rtKey = mkEnum {
      name = "nftablesRtKey";
      description = "nftables routing data key";
      enum = rtKeys;
    };
    ctDir = mkEnum {
      name = "nftablesCtDir";
      description = "nftables ct direction";
      enum = ctDirs;
    };
    ngMode = mkEnum {
      name = "nftablesNgMode";
      description = "nftables numgen mode";
      enum = ngModes;
    };
    fibResult = mkEnum {
      name = "nftablesFibResult";
      description = "nftables fib type";
      enum = fibResults;
    };
    fibFlag = mkEnum {
      name = "nftablesFibFlag";
      description = "nftables fib flag";
      enum = fibFlags;
    };
    socketKey = mkEnum {
      name = "nftablesSocketKey";
      description = "nftables socket key";
      enum = socketKeys;
    };
    osfKey = mkEnum {
      name = "nftablesOsfKey";
      description = "nftables osf key";
      enum = osfKeys;
    };
    osfTtl = mkEnum {
      name = "nftablesOsfTtl";
      description = "nftables osf ttl";
      enum = osfTtls;
    };
    payloadProtocol = mkEnum {
      name = "nftablesPayloadProtocol";
      description = "nftables payload protocol";
      enum = payloadProtocols;
    };
    payloadField = mkEnum {
      name = "nftablesPayloadField";
      description = "nftables payload field";
      enum = payloadFields;
    };
    exthdr = mkEnum {
      name = "nftablesExthdr";
      description = "nftables ipv6 extension header";
      enum = exthdrs;
    };
    exthdrField = mkEnum {
      name = "nftablesExthdrField";
      description = "nftables ipv6 extension header field";
      enum = exthdrFields;
    };
    tcpOption = mkEnum {
      name = "nftablesTcpOption";
      description = "nftables tcp option";
      enum = tcpOptions;
    };
    tcpOptionField = mkEnum {
      name = "nftablesTcpOptionField";
      description = "nftables tcp option field";
      enum = tcpOptionFields;
    };
    ipOption = mkEnum {
      name = "nftablesIpOption";
      description = "nftables ip option";
      enum = ipOptions;
    };
    ipOptionField = mkEnum {
      name = "nftablesIpOptionField";
      description = "nftables ip option field";
      enum = ipOptionFields;
    };
    sctpChunk = mkEnum {
      name = "nftablesSctpChunk";
      description = "nftables sctp chunk";
      enum = sctpChunks;
    };
    sctpChunkField = mkEnum {
      name = "nftablesSctpChunkField";
      description = "nftables sctp chunk field";
      enum = sctpChunkFields;
    };
    ctKey = mkEnum {
      name = "nftablesCtKey";
      description = "nftables ct expression key";
      enum = ctKeys;
    };
    ipsecDir = mkEnum {
      name = "nftablesIpsecDir";
      description = "nftables ipsec direction";
      enum = ipsecDirs;
    };
    ipsecKey = mkEnum {
      name = "nftablesIpsecKey";
      description = "nftables ipsec key";
      enum = ipsecKeys;
    };
    tableToDelete = mkTableType {
      finalMerge = x:
        if !x?handle && !x?name then throw "One of handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" ];
      withHandle = true;
    };
    dslCmdHack = type: lib.types.either (submodule' {
      skipNulls = false;
      finalMerge = x: x.__cmd__;
      freeformType = lib.types.unspecified;
      options.__cmd__ = lib.mkOption {
        inherit type;
      };
    }) type;
    # anything but delete
    tableToAdd = mkTableType { reqFields = [ "name" "family" ]; withExtraFields = true; };
    tableToWhatever = mkTableType { reqFields = [ "name" "family" ]; };
    chainToAdd = mkChainType {
      finalMerge = x:
        let
          baseDetect = [ "type" "hook" "prio" "policy" "dev" ];
          reqBase = [ "type" "hook" "prio" "policy" ];
          familyInfo = families.${x.family or ""} or {};
          reqBase' = reqBase ++ (lib.optionals (familyInfo.requireBaseChainDevice or false) [ "dev" ]);
          info = chainTypes.${x.type or ""} or {};
        in
          if
            builtins.any (k: builtins.elem k baseDetect) (builtins.attrNames x)
            && builtins.any (k: !x?${k}) reqBase'
          then
            throw "Base chains ${
              if x.family or "" == "netdev" then "in the netdev family " else ""
            }must have fields ${builtins.concatStringsSep ", " (map (s: "`${s}`") reqBase')} set"
          else if x.family or "" != "netdev" && x?dev then
            throw "I'm not sure about this, but I think non-netdev family chains can't have a device specified, check your code or open an issue!"
          else if x?family && info.families or null != null && !(builtins.elem x.family info.families) then
            throw "Chains of type ${x.type} can only be in families ${builtins.concatStringsSep ", " info.families}"
          else if x?hook && info.hooks or null != null && !(builtins.elem x.hook info.hooks) then
            throw "Chains of type ${x.type} can only be in hooks ${builtins.concatStringsSep ", " info.hooks}"
          else if x?hook && familyInfo.hooks or null != null && !(builtins.elem x.hook familyInfo.hooks) then
            throw "Chains of family ${x.family} can only be in hooks ${builtins.concatStringsSep ", " familyInfo.hooks}"
          else
            x // (if builtins.isString (x.prio or null) then
              let
                prioInfo = chainPriorities.${x.prio};
              in
                (if x?family && prioInfo.families or null != null && !(builtins.elem x.family prioInfo.families) then
                  throw "Priority ${x.prio} can only be used in families ${builtins.concatStringsSep ", " prioInfo.families}"
                else if x?hook && prioInfo.hooks or null != null && !(builtins.elem x.hook prioInfo.hooks) then
                  throw "Priority ${x.prio} can only be used in hooks ${builtins.concatStringsSep ", " prioInfo.hooks}"
                else {
                  prio = prioInfo.value (x.family or "");
                })
            else {});
      reqFields = [ "family" "table" "name" ];
      withExtraFields = true;
    };
    chainToDelete = mkChainType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      withHandle = true;
      reqFields = [ "family" "table" ];
    };
    chainToRename = mkChainType {
      withNewName = true;
      reqFields = [ "family" "table" "name" "newname" ];
    };
    # anything but add/delete/rename
    chainToWhatever = mkChainType {
      reqFields = [ "family" "table" "name" ];
    };
    ruleToAdd = mkRuleType {
      reqFields = [ "family" "table" "chain" "expr" ];
      withExpr = true;
      withHandle = true;
      withIndex = true;
      withComment = true;
    };
    ruleToReplace = mkRuleType {
      reqFields = [ "family" "table" "chain" "handle" "expr" ];
      withExpr = true;
      withHandle = true;
      withComment = true;
    };
    # anything but add/replace
    ruleToWhatever = mkRuleType {
      reqFields = [ "family" "table" "chain" "handle" ];
      withHandle = true;
    };
    setToAdd = mkSetType {
      isMap = false;
      reqFields = [ "family" "table" "name" "type" ];
      withExtraFields = true;
    };
    setToDelete = mkSetType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      withHandle = true;
      isMap = false;
      reqFields = [ "family" "table" ];
    };
    # anything but add/delete
    setToWhatever = mkSetType {
      isMap = false;
      reqFields = [ "family" "table" "name" ];
    };
    mapToAdd = mkSetType {
      isMap = true;
      reqFields = [ "family" "table" "name" "type" ];
      withExtraFields = true;
    };
    mapToDelete = mkSetType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      withHandle = true;
      isMap = true;
      reqFields = [ "family" "table" ];
    };
    # anything but add/delete
    mapToWhatever = mkSetType {
      isMap = true;
      reqFields = [ "family" "table" "name" ];
    };
    elementToAdd = mkElementType {
      reqFields = [ "family" "table" "name" "elem" ];
      withElem = true;
    };
    # anything but add
    elementToWhatever = mkElementType {
      reqFields = [ "family" "table" "name" "elem" ];
    };
    setElementToAdd = mkElementType {
      reqFields = [ "family" "table" "name" "elem" ];
      withElem = true;
      isMap = false;
    };
    # anything but add
    setElementToWhatever = mkElementType {
      reqFields = [ "family" "table" "name" ];
      isMap = false;
    };
    mapElementToAdd = mkElementType {
      reqFields = [ "family" "table" "name" "elem" ];
      withElem = true;
      isMap = true;
    };
    # anything but add
    mapElementToWhatever = mkElementType {
      reqFields = [ "family" "table" "name" ];
      isMap = true;
    };
    flowtableToAdd = mkFlowtableType {
      reqFields = [ "family" "table" "name" "hook" "prio" "dev" ];
      withExtraFields = true;
    };
    flowtableToDelete = mkFlowtableType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    # anything but add/delete
    flowTableToWhatever = mkFlowtableType {
      reqFields = [ "family" "table" "name" ];
    };
    counterToAdd = mkCounterType {
      reqFields = [ "family" "table" "name" ];
      withExtraFields = true;
    };
    counterToDelete = mkCounterType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    counterToWhatever = mkCounterType {
      reqFields = [ "family" "table" "name" ];
    };
    quotaToAdd = mkQuotaType {
      reqFields = [ "family" "table" "name" "bytes" "inv" ];
      withExtraFields = true;
    };
    quotaToDelete = mkQuotaType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    quotaToWhatever = mkQuotaType {
      reqFields = [ "family" "table" "name" ];
    };
    secmarkToAdd = mkSecmarkType {
      reqFields = [ "family" "table" "name" ];
      withExtraFields = true;
    };
    secmarkToDelete = mkSecmarkType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    secmarkToWhatever = mkSecmarkType {
      reqFields = [ "family" "table" "name" ];
    };
    ctHelperToAdd = mkCtHelperType {
      reqFields = [ "family" "table" "name" "type" "protocol" ];
      withExtraFields = true;
    };
    ctHelperToWhatever = mkCtHelperType {
      reqFields = [ "family" "table" "name" ];
    };
    limitToAdd = mkLimitType {
      reqFields = [ "family" "table" "name" "type" "rate" ];
      withExtraFields = true;
    };
    limitToDelete = mkLimitType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    limitToWhatever = mkLimitType {
      reqFields = [ "family" "table" "name" ];
    };
    ctTimeoutToAdd = mkCtTimeoutType {
      finalMerge = x:
        if x?policy then assert lib.assertMsg
          (builtins.all (k: builtins.elem k (builtins.attrNames connectionStates)) (builtins.attrNames x.policy))
          "Policy keys must be valid connection states"; x
        else x;
      reqFields = [ "family" "table" "name" "type" "protocol" "state" "value" ];
      withExtraFields = true;
    };
    ctTimeoutToDelete = mkCtTimeoutType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    ctTimeoutToWhatever = mkCtTimeoutType {
      reqFields = [ "family" "table" "name" ];
    };
    ctExpectationToAdd = mkCtExpectationType {
      reqFields = [ "family" "table" "name" "protocol" "dport" "timeout" "size" ];
      withExtraFields = true;
    };
    ctExpectationToDelete = mkCtExpectationType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    ctExpectationToWhatever = mkCtExpectationType {
      reqFields = [ "family" "table" "name" ];
    };
    synproxyToAdd = mkSynproxyType {
      reqFields = [ "family" "table" "name" "mss" "wscale" ];
      withExtraFields = true;
    };
    synproxyToDelete = mkSynproxyType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "family" "table" ];
      withHandle = true;
    };
    synproxyToWhatever = mkSynproxyType {
      reqFields = [ "family" "table" "name" ];
    };
    metainfoCommand = submodule' {
      options.version = mkNullOption {
        type = lib.types.str;
      };
      options.release_name = mkNullOption {
        type = lib.types.str;
      };
      options.json_schema_version = lib.mkOption {
        type = lib.types.int;
        default = 1;
      };
    };
    addCommand = oneOf' {
      name = "nftablesAddCommand";
      description = "add command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "Add ${k}.";
      })) {
        table = types.tableToWhatever;
        chain = types.chainToAdd;
        rule = types.ruleToAdd;
        set = types.setToAdd;
        map = types.mapToAdd;
        element = types.elementToAdd;
        flowtable = types.flowtableToAdd;
        counter = types.counterToAdd;
        quota = types.quotaToAdd;
        secmark = types.secmarkToAdd;
        "ct helper" = types.ctHelperToAdd;
        limit = types.limitToAdd;
        "ct timeout" = types.ctTimeoutToAdd;
        "ct expectation" = types.ctExpectationToAdd;
        # synproxy = types.synproxyToAdd;
      };
    };
    replaceCommand = lib.types.submodule {
      options = {
        rule = lib.mkOption {
          type = types.ruleToReplace;
          description = "rule to replace";
        };
      };
    };
    createCommand = oneOf' {
      name = "nftablesCreateCommand";
      description = "nftables create command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "Create ${k} (same as add, but ensure it doesn't already exist).";
      })) {
        table = types.tableToWhatever;
        chain = types.chainToAdd;
        rule = types.ruleToAdd;
        set = types.setToAdd;
        map = types.mapToAdd;
        element = types.elementToAdd;
        flowtable = types.flowtableToAdd;
        counter = types.counterToAdd;
        quota = types.quotaToAdd;
        secmark = types.secmarkToAdd;
        "ct helper" = types.ctHelperToAdd;
        limit = types.limitToAdd;
        "ct timeout" = types.ctTimeoutToAdd;
        "ct expectation" = types.ctExpectationToAdd;
        # synproxy = types.synproxyToAdd;
      };
    };
    insertCommand = lib.types.submodule {
      options = {
        rule = lib.mkOption {
          type = types.dslCmdHack types.ruleToAdd;
          description = "rule to insert (prepend)";
        };
      };
    };
    deleteCommand = oneOf' {
      name = "nftablesDeleteCommand";
      description = "nftables delete command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "Delete ${k}.";
      })) {
        table = types.tableToDelete;
        chain = types.chainToDelete;
        rule = types.ruleToWhatever;
        set = types.setToDelete;
        map = types.mapToDelete;
        element = types.elementToWhatever;
        flowtable = types.flowtableToDelete;
        counter = types.counterToDelete;
        quota = types.quotaToDelete;
        secmark = types.secmarkToDelete;
        "ct helper" = types.ctHelperToWhatever;
        limit = types.limitToDelete;
        "ct timeout" = types.ctTimeoutToDelete;
        "ct expectation" = types.ctExpectationToDelete;
        # synproxy = types.synproxyToWhatever;
      };
    };
    destroyCommand = oneOf' {
      name = "nftablesDestroyCommand";
      description = "nftables destroy command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "Destroy ${k}.";
      })) {
        table = types.tableToDelete;
        chain = types.chainToDelete;
        rule = types.ruleToWhatever;
        set = types.setToDelete;
        map = types.mapToDelete;
        element = types.elementToWhatever;
        flowtable = types.flowtableToDelete;
        counter = types.counterToDelete;
        quota = types.quotaToDelete;
        secmark = types.secmarkToDelete;
        "ct helper" = types.ctHelperToWhatever;
        limit = types.limitToDelete;
        "ct timeout" = types.ctTimeoutToDelete;
        "ct expectation" = types.ctExpectationToDelete;
        # synproxy = types.synproxyToWhatever;
      };
    };
    null = lib.mkOptionType {
      name = "null";
      descriptionClass = "noun";
      check = x: x == null;
      merge = loc: defs: null;
      emptyValue = { value = null; };
    };
    listCommand = oneOf' {
      name = "nftablesListCommand";
      description = "nftables list command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "List ${k}.";
      })) {
        table = types.tableToWhatever;
        tables = types.null;
        chain = types.chainToWhatever;
        chains = types.null;
        set = types.setToWhatever;
        sets = types.null;
        map = types.mapToWhatever;
        maps = types.null;
        counter = types.counterToWhatever;
        counters = types.null;
        quota = types.quotaToWhatever;
        quotas = types.null;
        secmark = types.secmarkToWhatever;
        secmarks = types.null;
        "ct helper" = types.ctHelperToWhatever;
        "ct helpers" = types.null;
        limit = types.limitToWhatever;
        limits = types.null;
        ruleset = types.null;
        meter = types.meterToWhatever;
        meters = types.null;
        flowtable = types.flowtableToWhatever;
        flowtables = types.null;
        "ct timeout" = types.ctTimeoutToWhatever;
        "ct timeouts" = types.null;
        "ct expectation" = lib.types.nullOr types.ctExpectationToWhatever;
        "ct expectations" = types.null;
        # synproxy = types.synproxyToWhatever;
        # synproxys = types.synproxyToAdd;
      };
    };
    resetCommand = oneOf' {
      name = "nftablesListCommand";
      description = "nftables list command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "Reset ${k}.";
      })) {
        counter = types.counterToWhatever;
        counters = types.null;
        quota = types.quotaToWhatever;
        quotas = types.null;
        rule = types.ruleToWhatever;
        rules = types.null;
      };
    };
    flushCommand = oneOf' {
      name = "nftablesListCommand";
      description = "nftables list command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = types.dslCmdHack v;
        description = "Flush ${k}.";
      })) {
        table = types.tableToWhatever;
        chain = types.chainToWhatever;
        set = types.setToWhatever;
        map = types.mapToWhatever;
        meter = types.meterToWhatever;
        ruleset = types.null;
      };
    };
    renameCommand = lib.types.submodule {
      options = {
        rule = lib.mkOption {
          type = types.chainToRename;
          description = "chain to rename";
        };
      };
    };
    command = oneOf' {
      name = "nftablesCommand";
      description = "nftables command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} command.\n\n${v.description}";
      })) {
        metainfo = {
          type = types.metainfoCommand;
          description = "Specify ruleset metainfo.";
        };
        add = {
          type = types.addCommand;
          description = "Add a new ruleset element to the kernel.";
        };
        replace = {
          type = types.replaceCommand;
          description = lib.mdDoc "Replace a rule. In rule, the **handle** property is mandatory and identifies the rule to be replaced.";
        };
        create = {
          type = types.createCommand;
          description = lib.mdDoc "Identical to **add** command, but returns an error if the object already exists.";
        };
        insert = {
          type = types.insertCommand ;
          description = lib.mdDoc "This command is identical to **add** for rules, but instead of appending the rule to the chain by default, it inserts at first position. If a **handle** or **index** property is given, the rule is inserted before the rule identified by those properties.";
        };
        delete = {
          type = types.deleteCommand;
          description = lib.mdDoc "Delete an object from the ruleset. Only the minimal number of properties required to uniquely identify an object is generally needed in *ADD_OBJECT*. For most ruleset elements, this is **family** and **table** plus either **handle** or **name** (except rules since they don’t have a name).";
        };
        destroy = {
          type = types.destroyCommand;
          description = "Undocumented upstream";
        };
        list = {
          type = types.listCommand;
          description = lib.mdDoc "List ruleset elements. The plural forms are used to list all objects of that kind, optionally filtered by **family** and for some, also **table**.";
        };
        reset = {
          type = types.resetCommand;
          description = "Reset state in suitable objects, i.e. zero their internal counter.";
        };
        flush = {
          type = types.flushCommand;
          description = lib.mdDoc "Empty contents in given object, e.g. remove all chains from given **table** or remove all elements from given **set**.";
        };
        rename = {
          type = types.renameCommand;
          description = lib.mdDoc "Rename a chain. The new name is expected in a dedicated property named **newname**.";
        };
      };
    };
    # not really ruleset, just commands
    ruleset = lib.types.submodule {
      options.nftables = lib.mkOption {
        type = lib.types.listOf types.command;
        description = "Commands to execute.";
        default = [ ];
      };
    };
    # next: Statements
    jumpStatement = lib.types.submodule {
      options.target = lib.mkOption { type = types.chainName; description = "jump target"; };
    };
    jumpExpression = types.jumpStatement;
    gotoStatement = lib.types.submodule {
      options.target = lib.mkOption { type = types.chainName; description = "goto target"; };
    };
    gotoExpression = types.gotoStatement;
    matchStatement = submodule' {
      finalMerge = { left, right, ... } @ ret:
        assert lib.assertMsg ((isValidExpr 0 left) && (isValidExpr CTX_F_RHS right)) "Match statements' expressions are invalid in this context"; ret;
      skipNulls = false;
      options.left = lib.mkOption { type = types.expression; description = "Left hand side of this match."; };
      options.right = lib.mkOption { type = types.expression; description = "Right hand side of this match."; };
      options.op = lib.mkOption { type = types.operator; description = "Operator indicating the type of comparison."; };
    };
    counterStatement = lib.types.submodule {
      options.packets = lib.mkOption {
        type = lib.types.ints.unsigned;
        description = "Packets counted";
      };
      options.bytes = lib.mkOption {
        type = lib.types.ints.unsigned;
        description = "Byte counter value.";
      };
    };
    mangleStatement = submodule' {
      finalMerge = { key, value }@ret:
        if key?exthdr || key?payload || key?meta || key?ct || key?"ct helper" then
          assert lib.assertMsg
            (isValidExpr CTX_F_MANGLE key && isValidExpr CTX_F_STMT value)
            "Mangle statements' expressions are invalid in this context";
          ret
        else throw ''Key must be given as an "exthdr", "payload", "meta", "ct" or "ct helper" expression.'';

      options.key = lib.mkOption {
        type = types.expression;
        description = lib.mdDoc "The packet data to be changed, given as an **exthdr**, **payload**, **meta**, **ct** or **ct helper** expression.";
      };
      options.value = lib.mkOption {
        type = types.expression;
        description = "Value to change data to.";
      };
    };
    quotaStatement = submodule' {
      finalMerge = x: if x?used_unit && !x?used then throw "If quota stmt has used_unit, must specify used as well" else x;
      options.val = lib.mkOption {
        type = lib.types.ints.unsigned;
        description = "Quota value.";
      };
      options.val_unit = lib.mkOption {
        type = types.byteUnit;
        description = lib.mdDoc ''Unit of **val**, e.g. **"kbytes"** or **"mbytes"**. If omitted, defaults to **"bytes"**.'';
        defaultText = lib.literalExpression "bytes";
      };
      options.used = mkNullOption {
        type = types.ints.unsigned;
        description = "Quota used so far. Optional on input. If given, serves as initial value.";
      };
      options.used_unit = mkNullOption {
        type = types.byteUnit;
        description = lib.mdDoc ''Unit of **used**. Defaults to **"bytes"**.'';
        defaultText = lib.literalExpression "bytes";
      };
      options.inv = mkNullOption {
        type = lib.types.bool;
        description = lib.mdDoc "If **true**, will match if the quota has been exceeded. Defaults to **false**.";
        defaultText = lib.literalExpression false;
      };
    };
    limitStatement = submodule' {
      finalMerge = x: if (x.rate_unit or "packets") == "packets" && x?burst_unit then throw "burst_unit is ignored when rate_unit is \"packets\", don't set it" else x;
      options.rate = lib.mkOption {
        type = lib.types.ints.unsigned;
        description = "Rate value to limit to.";
      };
      options.rate_unit = mkNullOption {
        type = types.rateUnit;
        description = lib.mdDoc ''Unit of **rate**, e.g. **"packets"** or **"mbytes"**. Defaults to **"packets"**.'';
        defaultText = lib.literalExpression "packets";
      };
      options.per = lib.mkOption {
        type = types.timeUnit;
        description = lib.mdDoc ''Denominator of rate, e.g. **"week"** or **"minutes"**.'';
      };
      options.burst = mkNullOption {
        type = lib.types.ints.u32;
        description = lib.mdDoc "Burst value. Defaults to **0**.";
        defaultText = lib.literalExpression 0;
      };
      options.burst_unit = mkNullOption {
        type = types.byteUnit;
        description = lib.mdDoc ''Unit of burst, ignored if rate_unit is **"packets"**. Defaults to **"bytes"**.'';
        defaultText = lib.literalExpression "bytes";
      };
      options.inv = mkNullOption {
        type = lib.types.bool;
        description = lib.mdDoc "If **true**, matches if the limit was exceeded. Defaults to **false**.";
        defaultText = lib.literalExpression false;
      };
    };
    fwdStatement = submodule' {
      finalMerge = { dev, ... } @ ret:
        if (ret?family && !ret?addr) || (ret?addr && !ret?family)
        then throw "If at least one of `addr` or `family` is given, both must be present."
        else assert lib.assertMsg
          (isValidExpr CTX_F_STMT dev && (!ret?addr || isValidExpr CTX_F_STMT ret.addr))
          "Fwd statement's expressions are invalid in this context"; ret;
      options.dev = lib.mkOption {
        type = types.expression;
        description = "Interface to forward the packet on.";
      };
      options.family = mkNullOption {
        type = types.ipFamily;
        description = lib.mdDoc "Family of **addr**.";
      };
      options.addr = mkNullOption {
        type = types.expression;
        description = "IP(v6) address to forward the packet to.";
      };
    };
    dupStatement = submodule' {
      finalMerge = ret:
        assert lib.assertMsg
          (isValidExpr CTX_F_STMT ret.addr && (!ret?dev || isValidExpr CTX_F_STMT ret.dev))
          "Dup statement's expressions are invalid in this context";
        ret;
      options.addr = lib.mkOption {
        type = types.expression;
        description = "Address to duplicate packet to.";
      };
      options.dev = mkNullOption {
        type = types.expression;
        description = "Interface to duplicate packet on. May be omitted to not specify an interface explicitly.";
      };
    };
    snatStatement = submodule' {
      finalMerge = ret:
        assert lib.assertMsg
          ((!ret?addr || isValidExpr CTX_F_STMT ret.addr) && (!ret?port || isValidExpr CTX_F_STMT ret.port))
          "Nat statement's expressions are invalid in this context";
        ret;
      options.addr = mkNullOption {
        type = types.expression;
        description = "Address to translate to.";
      };
      options.family = mkNullOption {
        type = types.ipFamily;
        description = "Family of addr, either ip or ip6. Required in inet table family.";
      };
      options.port = mkNullOption {
        type = types.expression;
        description = "Port to translate to.";
      };
      options.flags = mkNullOption {
        type = lib.types.either types.natFlag (lib.types.listOf types.natFlag);
        description = "Flag(s).";
      };
      options.type_flags = mkNullOption {
        type = lib.types.either types.natTypeFlag (lib.types.listOf types.natTypeFlag);
        description = "Type flag(s).";
      };
    };
    dnatStatement = types.snatStatement;
    masqueradeStatement = submodule' {
      finalMerge = ret:
        assert lib.assertMsg
          (!ret?port || isValidExpr CTX_F_STMT ret.port)
          "Nat statement's expressions are invalid in this context";
        ret;
      options.port = mkNullOption {
        type = lib.types.port;
        description = "Port to translate to.";
      };
      options.flags = mkNullOption {
        type = lib.types.either types.natFlag (lib.types.listOf types.natFlag);
        description = "Flag(s).";
      };
      options.type_flags = mkNullOption {
        type = lib.types.either types.natTypeFlag (lib.types.listOf types.natTypeFlag);
        description = "Type flag(s).";
      };
    };
    redirectStatement = types.masqueradeStatement;
    rejectStatement = submodule' {
      finalMerge = ret:
        if ret.expr or null != null && ret.type or null == "tcp reset"
        then throw "ICMP reject codes are only valid for rejections with type `icmp`/`icmpv6`/`icmpx`"
        else assert lib.assertMsg
          (!ret?expr || isImmediateExpr ret.expr)
          "Reject statement's expression is invalid in this context";
        ret;
      options.type = mkNullOption {
        type = types.rejectType;
        description = lib.mdDoc ''Type of reject, either **"tcp reset"**, **"icmpx"**, **"icmp"** or **"icmpv6"**.'';
      };
      options.expr = mkNullOption {
        type = types.expression;
        description = "ICMP code to reject with.";
      };
    };
    setStatement = submodule' {
      finalMerge = ret:
        assert lib.assertMsg
          (!ret?elem || isValidExpr CTX_F_SES ret.elem)
          "Set statement's expression is invalid in this context";
        ret;
      options.op = lib.mkOption {
        description = lib.mdDoc ''Operator on set, either **"add"** or **"update"**. Undocumented upstream: **"delete"**'';
        type = types.setOp;
      };
      options.elem = lib.mkOption {
        description = "Set element to add or update.";
        type = types.expression;
      };
      options.set = lib.mkOption {
        description = "Set reference.";
        type = types.setReference;
      };
      options.stmt = mkNullOption {
        description = "Undocumented upstream";
        type = types.statement;
      };
    };
    logStatement = submodule' {
      options.prefix = mkNullOption {
        description = "Prefix for log entries.";
        type = lib.types.str;
      };
      options.group = mkNullOption {
        description = "Log group.";
        type = lib.types.ints.u16;
      };
      options.snaplen = mkNullOption {
        description = "Snaplen for logging.";
        type = lib.types.ints.u32;
      };
      options.queue-threshold = mkNullOption {
        description = "Queue threshold.";
        type = lib.types.ints.u16;
      };
      options.level = mkNullOption {
        description = lib.mdDoc ''Log level. Defaults to **"warn"**.'';
        type = types.logLevel;
        defaultText = lib.literalExpression "warn";
      };
      options.flags = mkNullOption {
        description = "Log flags.";
        type = lib.types.either types.logFlag (lib.types.listOf types.logFlag);
        defaultText = lib.literalExpression [ ];
      };
    };
    meterStatement = submodule' {
      finalMerge = { key, ... }@ret:
        assert lib.assertMsg
          (isValidExpr CTX_F_SES key)
          "Meter statement's key expression is invalid in this context";
        ret;
      options.name = lib.mkOption {
        description = "Meter name.";
        type = lib.types.str;
      };
      options.key = lib.mkOption {
        description = "Meter key.";
        type = types.expression;
      };
      options.stmt = lib.mkOption {
        description = "Meter statement.";
        type = types.statement;
      };
      options.size = mkNullOption {
        description = "Meter size.";
        type = lib.types.ints.u32;
      };
    };
    queueStatement = submodule' {
      finalMerge = ret:
        assert lib.assertMsg
          (!ret?num || isValidExpr CTX_F_STMT ret.num)
          "Queue statement's num expression is invalid in this context";
        ret;
      skipNulls = false;
      options.num = mkNullOption {
        description = "Queue number.";
        type = types.expression;
      };
      options.flags = mkNullOption {
        description = "Queue flags.";
        type = lib.types.either types.queueFlag (lib.types.listOf types.queueFlag);
      };
    };
    vmapStatement = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Map key.";
        type = types.expression;
      };
      options.data = lib.mkOption {
        description = "Mapping expression consisting of a set with value/verdict pairs.";
        type = types.expression;
      };
    };
    ctCountStatement = submodule' {
      options.val = lib.mkOption {
        description = "Connection count threshold.";
        type = lib.types.ints.u32;
      };
      options.inv = mkNullOption {
        type = lib.types.bool;
        description = lib.mdDoc "If **true**, match if **val** was exceeded. If omitted, defaults to **false**.";
        defaultText = lib.literalExpression false;
      };
    };
    xtStatement = lib.types.submodule {
      options.type = lib.mkOption {
        type = types.xtType;
      };
      options.name = lib.mkOption {
        type = lib.types.str;
      };
    };
    flowStatement = lib.types.submodule {
      options.op = lib.mkOption {
        type = types.flowtableOp;
        default = flowtableOps.add;
        description = "Undocumented upstream (flowtable operation)";
      };
      options.name = lib.mkOption {
        type = types.flowtableReference;
        description = "Undocumented upstream (flowtable name prefixed with \"@\")";
      };
    };
    tproxyStatement = submodule' {
      finalMerge = ret:
        assert lib.assertMsg
          ((!ret?addr || isValidExpr CTX_F_STMT ret.addr) && (!ret?port || isValidExpr CTX_F_STMT ret.port))
          "Tproxy statement's expressions are invalid in this context";
        ret;
      options.addr = mkNullOption {
        type = types.expression;
        description = "Address to proxy to.";
      };
      options.family = mkNullOption {
        type = types.ipFamily;
        description = "Family of addr, either ip or ip6. Required in inet table family (or not, this is undocumented).";
      };
      options.port = mkNullOption {
        type = types.expression;
        description = "Port to proxy to.";
      };
    };
    synproxyStatement = submodule' {
      chk = x: x?mss || x?wscale || x?flags;
      options.mss = mkNullOption {
        type = types.ints.u16;
        description = "Maximum segment size announced to clients. This must match the backend.";
      };
      options.wscale = mkNullOption {
        type = types.ints.u8;
        description = "Window scale announced to clients. This must match the backend.";
      };
      options.flags = mkNullOption {
        type = lib.types.either types.synproxyFlag (lib.types.listOf types.synproxyFlag);
        description = "Optional flags.";
      };
    };
    statement = oneOf' {
      name = "nftablesStatement";
      description = "nftables statement";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} statement.\n\n${v.description}";
      })) {
        # verdicts
        accept = {
          type = types.null; 
          description = "Terminate ruleset evaluation and accept the packet";
        };
        drop = {
          type = types.null;
          description = "Terminate ruleset evaluation and drop the packet.";
        };
        continue = {
          type = types.null;
          description = "Continue ruleset evaluation with the next rule.";
        };
        return = {
          type = types.null;
          description = "Return from the current chain and continue evaluation at the next rule in the last chain.";
        };
        jump = {
          type = types.jumpStatement;
          description = "Continue evaluation at the first rule in chain, pushing the current position to the call stack.";
        };
        goto = {
          type = types.gotoStatement;
          description = lib.mdDoc "Similar to **jump**, but the current position is not pushed to the call stack.";
        };
        match = {
          type = types.matchStatement;
          description = lib.mdDoc ''
            Unlike with the standard API, the operator is mandatory here. In the standard API, a missing operator may be resolved in two ways, depending on the type of expression on the RHS:

            - If the RHS is a bitmask or a list of bitmasks, the expression resolves into a binary operation with the inequality operator, like this: LHS & RHS != 0.
            - In any other case, the equality operator is simply inserted.

            For the non-trivial first case, the JSON API supports the in operator.
        '';
        };
        counter = {
          type = lib.types.nullOr (lib.types.either types.counterStatement (types.expression' { chk = isValidExpr CTX_F_STMT; }));
          description = lib.mdDoc ''
            This object represents a byte/packet counter. In input, no properties are required. If given, they act as initial values for the counter.

            The first form creates an anonymous counter which lives in the rule it appears in. The second form specifies a reference to a named counter object.
          '';
        };
        mangle = {
          type = types.mangleStatement;
          description = "This changes the packet data or meta info.";
        };
        quota = {
          type = lib.types.either types.quotaStatement (types.expression' { chk = isValidExpr CTX_F_STMT; });
          description = "The first form creates an anonymous quota which lives in the rule it appears in. The second form specifies a reference to a named quota object.";
        };
        limit = {
          type = lib.types.either types.limitStatement (types.expression' { chk = isValidExpr CTX_F_STMT; });
          description = "The first form creates an anonymous quota which lives in the rule it appears in. The second form specifies a reference to a named limit object.";
        };
        fwd = {
          type = types.fwdStatement;
          description = "Forward a packet to a different destination.";
        };
        notrack = {
          type = types.null;
          description = "Disable connection tracking for the packet.";
        };
        dup = {
          type = types.dupStatement; 
          description = "Duplicate a packet to a different destination.";
        };
        # NAT
        snat = {
          type = types.snatStatement;
          description = "Perform Source Network Address Translation.";
        };
        dnat = {
          type = types.dnatStatement;
          description = "Perform Destination Network Address Translation.";
        };
        masquerade = {
          type = types.masqueradeStatement;
          description = "Perform Source Network Address Translation to the outgoing interface's IP address.";
        };
        redirect = {
          type = types.redirectStatement;
          description = "Perform Destination Network Address Translation to the local host's IP address.";
        };
        reject = {
          type = types.rejectStatement;
          description = "Reject the packet and send the given error reply.";
        };
        set = {
          type = types.setStatement;
          description = "Dynamically add/update elements to a set.";
        };
        log = {
          type = types.logStatement;
          description = "Log the packet.";
        };
        "ct helper" = {
          type = types.expression' { chk = isValidExpr CTX_F_STMT; };
          description = "Enable the specified conntrack helper for this packet.";
        };
        meter = {
          type = types.meterStatement;
          description = "Apply a given statement using a meter.";
        };
        queue = {
          type = types.queueStatement;
          description = "Terminate ruleset evaluation and queue the packet to userspace.";
        };
        vmap = {
          type = types.vmapStatement;
          description = "Apply a verdict conditionally.";
        };
        "ct count" = {
          type = types.ctCountStatement;
          description = "Limit the number of connections using conntrack.";
        };
        "ct timeout" = {
          type = types.expression' { chk = isValidExpr CTX_F_STMT; };
          description = "Assign connection tracking timeout policy.";
        };
        "ct expectation" = {
          type = types.expression' { chk = isValidExpr CTX_F_STMT; };
          description = "Assign connection tracking expectation.";
        };
        xt = {
          type = types.xtStatement;
          description = lib.mdDoc ''
            This represents an xt statement from xtables compat interface. It is a fallback if translation is not available or not complete.

            Seeing this means the ruleset (or parts of it) were created by **iptables-nft** and one should use that to manage it.

            **BEWARE:** nftables won’t restore these statements.
          '';
        };
        flow = {
          type = types.flowStatement;
          description = "A flow statement allows us to select what flows you want to accelerate forwarding through layer 3 network stack bypass. You have to specify the flowtable name where you want to offload this flow.";
        };
        tproxy = {
          type = types.tproxyStatement;
          description = "Tproxy redirects the packet to a local socket without changing the packet header in any way. If any of the arguments is missing the data of the incoming packet is used as parameter. Tproxy matching requires another rule that ensures the presence of transport protocol header is specified.";
        };
        synproxy = {
          type = lib.types.nullOr (lib.types.either types.synproxyStatement (types.expression' { chk = isValidExpr CTX_F_STMT; }));
          description = "This statement will process TCP three-way-handshake parallel in netfilter context to protect either local or backend system. This statement requires connection tracking because sequence numbers need to be translated.";
        };
        reset = {
          type = types.expression' { chk = isValidExpr 0; };
          description = "Undocumented upstream (set this to a tcp option expr to reset it)";
        };
        secmark = {
          type = types.expression' { chk = isValidExpr CTX_F_STMT; };
          description = "Undocumented upstream";
        };
      };
    };
    rangeExpression = types.listOfSize2 types.expression;
    mapExpression = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Map key.";
        type = types.expression;
      };
      options.data = lib.mkOption {
        description = "Mapping expression consisting of a set with value/target pairs.";
        type = types.expression;
      };
    };
    prefixExpression = lib.types.submodule {
      options.addr = lib.mkOption {
        description = "Address part of an address prefix.";
        type = types.expression;
      };
      options.len = lib.mkOption {
        description = "Prefix length.";
        type = lib.types.ints.between 0 128;
      };
    };
    rawPayloadExpression = submodule' {
      skipNulls = false;
      options.base = lib.mkOption {
        description = "Payload base.";
        type = types.payloadBase;
      };
      options.offset = lib.mkOption {
        description = "Payload offset.";
        type = lib.types.ints.u32;
      };
      options.len = lib.mkOption {
        description = "Payload length.";
        type = lib.types.ints.u32;
      };
    };
    namedPayloadExpression = submodule' {
      finalMerge = { protocol, field }@ret: (let
        inherit (payloadProtocols.${protocol} or {}) fields;
      in
        if laxEnums || fields?${field} then ret
        else throw "Protocol ${protocol} only supports fields ${builtins.concatStringsSep ", " (builtins.attrNames fields)}");
      skipNulls = false;
      options.protocol = lib.mkOption {
        description = "Payload reference packet header protocol.";
        type = types.payloadProtocol;
      };
      options.field = lib.mkOption {
        description = "Payload reference packet header field.";
        type = types.payloadField;
      };
    };
    payloadExpression = oneOf' {
      name = "nftablesPayloadExpression";
      description = "nftables payload expression";
      types = [ types.rawPayloadExpression types.namedPayloadExpression ];
    };
    exthdrExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (exthdrs.${name} or {}) fields;
      in
      if laxEnums || !ret?field || fields?${ret.field}
      then
        (if ret?field && ret?offset then throw "Only one of field and offset of exthdr may be true"
        else if !ret?offset && ret.name == "rt0" then throw "Must have offset specified with exthdr rt0"
        else if ret?offset && ret.name != "rt0" then throw "Must not have offset specified with any exthdr other than rt0"
        else ret)
      else throw "IPv6 extension header ${name} only supports fields ${builtins.concatStringsSep ", " (builtins.attrNames fields)}";
      options.name = lib.mkOption {
        description = "IPv6 extension header name.";
        type = types.exthdr;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "Field name. If this property is not given, the expression is to be used as a header existence check in a **match** statement with a boolean on the right hand side.";
        type = types.exthdrField;
      };
      options.offset = mkNullOption {
        description = lib.mdDoc "Field **offset** (used only for **rt0** protocol).";
        type = lib.types.ints.u16;
      };
    };
    # undocumented
    rawTcpOptionExpression = lib.types.submodule {
      options.base = lib.mkOption {
        description = "TCP option kind (numeric).";
        type = lib.types.ints.u8;
      };
      options.offset = lib.mkOption {
        description = "Data byte offset in TCP option.";
        type = lib.types.ints.u32;
      };
      options.len = lib.mkOption {
        description = "Data byte length in TCP option.";
        type = lib.types.ints.u32;
      };
    };
    namedTcpOptionExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (tcpOptions.${name}) fields;
      in
        if laxEnums || !ret?field || fields?${ret.field} then ret
        else throw "TCP option ${name} only supports fields ${builtins.concatStringsSep ", " (builtins.attrNames fields)}";
      options.name = lib.mkOption {
        description = "TCP option name.";
        type = types.tcpOption;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "TCP option field. If this property is not given, the expression is to be used as a TCP option existence check in a **match** statement with a boolean on the right hand side.";
        type = types.tcpOptionField;
      };
    };
    tcpOptionExpression = oneOf' {
      name = "nftablesTcpOptionExpression";
      description = "nftables tcp option expression";
      types = [ types.rawTcpOptionExpression types.namedTcpOptionExpression ];
    };
    ipOptionExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (ipOptions.${name}) fields;
      in
        if laxEnums || !ret?field || fields?${ret.field} then ret
        else throw "IP option ${name} only supports fields ${builtins.concatStringsSep ", " (builtins.attrNames fields)}";
      options.name = lib.mkOption {
        description = "IP option header name.";
        type = types.ipOption;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "IP option header field. If this property is not given, the expression is to be used as an IP option existence check in a **match** statement with a boolean on the right hand side.";
        type = types.ipOptionField;
      };
    };
    sctpChunkExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (sctpChunks.${name}) fields;
      in
        if laxEnums || !ret?field || fields?${ret.field} then ret
        else throw "SCTP chunk ${name} only supports fields ${builtins.concatStringsSep ", " (builtins.attrNames fields)}";
      options.name = lib.mkOption {
        description = "SCTP chunk name.";
        type = types.sctpChunk;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "SCTP chunk field. If this property is not given, the expression is to be used as an SCTP chunk existence check in a **match** statement with a boolean on the right hand side.";
        type = types.sctpChunkField;
      };
    };
    metaExpression = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Meta key.";
        type = types.metaKey;
      };
    };
    rtExpression = submodule' {
      options.key = lib.mkOption {
        description = "Routing data key.";
        type = types.rtKey;
      };
      options.family = mkNullOption {
        description = "Routing data IP family. This property is optional and defaults to unspecified.";
        type = types.ipFamily;
      };
    };
    ctExpression = submodule' {
      finalMerge = { key, ... }@ret: let
        info = ctKeys.${key} or {};
        dir = info.dir or null;
        # family = info.family or null;
      in
        if dir == true && !ret?dir then throw "You must provide a direction for CT key ${key}."
        else if dir == false && ret?dir then throw "You must not provide a direction for CT key ${key}."
        # else if family == true && !ret?family then throw "You must provide an IP family for CT key ${key}."
        # else if family == false && ret?family then throw "You must not provide an IP family for CT key ${key}."
        else if ret?family then throw "Look, I know that you might expect that ct expressions have a property \"family\" - I wouldn't blame you, given that the official docs explain what it does... but actually inside the code it has absolutely no effect. Instead, you have to do this - specify \"ip saddr\" or \"ip6 saddr\" instead of \"saddr\", same for \"daddr\"."
        else ret;
      options.key = lib.mkOption {
        description = "CT key";
        type = types.ctKey;
      };
      options.family = mkNullOption {
        description = "IP family.";
        type = types.ipFamily;
      };
      options.dir = mkNullOption {
        description = lib.mdDoc "Some CT keys do not support a direction. In this case, **dir** must not be given.";
        type = types.ctDir;
      };
    };
    ipsecExpression = submodule' {
      finalMerge = { key, ... }@ret: let
        info = ctKeys.${key} or {};
        needsFamily = info.needsFamily or false;
      in
        if needsFamily && !ret?family then throw "You must provide a family for IPSec key ${key}"
        else if (ret.spnum or 0) > 255 then throw "Max spnum allowed is 255"
        else ret;
      options.key = lib.mkOption {
        description = "Undocumented upstream";
        type = types.ipsecKey;
      };
      options.family = mkNullOption {
        description = "IP family.";
        type = types.ipFamily;
      };
      options.dir = mkNullOption {
        description = "Undocumented upstream";
        type = types.ipsecDir;
      };
      options.spnum = mkNullOption {
        description = "Undocumented upstream";
        type = lib.types.ints.u8;
      };
    };
    numgenExpression = submodule' {
      options.mode = lib.mkOption {
        description = "Numgen mode";
        type = types.ngMode;
      };
      options.mod = lib.mkOption {
        description = "Number modulus (number of different values possible).";
        type = lib.types.ints.u32;
      };
      options.offset = mkNullOption {
        description = "Number offset (added to the result). Defaults to 0.";
        type = lib.types.ints.u32;
        defaultText = lib.literalExpression 0;
      };
    };
    jhashExpression = submodule' {
      options.mod = lib.mkOption {
        description = "Hash modulus (number of possible different values).";
        type = lib.types.ints.u32;
      };
      options.offset = mkNullOption {
        description = "Hash offset (min value). Defaults to 0.";
        type = lib.types.ints.u32;
        defaultText = lib.literalExpression 0;
      };
      options.expr = lib.mkOption {
        description = "Expression to hash.";
        type = types.expression;
      };
      options.seed = mkNullOption {
        description = "Hash seed. Defaults to 0.";
        type = lib.types.ints.u32;
        defaultText = lib.literalExpression 0;
      };
    };
    symhashExpression = submodule' {
      options.mod = lib.mkOption {
        description = "Hash modulus (number of possible different values).";
        type = lib.types.ints.u32;
      };
      options.offset = mkNullOption {
        description = "Hash offset (min value). Defaults to 0.";
        type = lib.types.ints.u32;
        defaultText = lib.literalExpression 0;
      };
    };
    fibExpression = submodule' {
      finalMerge = fib:
        let
          flags = lib.toList fib.flags;
          saddr = builtins.elem "saddr" flags;
          daddr = builtins.elem "daddr" flags;
          iif = builtins.elem "iif" flags;
          oif = builtins.elem "oif" flags;
        in
          if saddr && daddr then throw "Only one flag out of saddr/daddr may be set in fib"
          else if !saddr && !daddr then throw "One flag out of saddr/daddr must be set in fib"
          else if iif && oif then throw "At most one one flag out of iif/oif may be set in fib"
          else fib;
      skipNulls = false;
      options.result = lib.mkOption {
        description = "Fib expression type.";
        type = types.fibResult;
      };
      options.flags = lib.mkOption {
        description = "Fib expression type.";
        type = lib.types.either types.fibFlag (lib.types.listOf types.fibFlag);
      };
    };
    binOpExpression = types.listOfSize2 types.expression;
    elemExpression = submodule' {
      options.val = lib.mkOption {
        description = "Set element.";
        type = types.expression;
      };
      options.timeout = mkNullOption {
        description = lib.mdDoc "Timeout value for sets/maps with flag **timeout** (in seconds).";
        type = lib.types.ints.unsigned;
      };
      options.expires = mkNullOption {
        description = "The time until given element expires (in seconds), useful for ruleset replication only.";
        type = lib.types.ints.unsigned;
      };
      options.comment = mkNullOption {
        description = "Per element comment field";
        type = lib.types.str;
      };
    };
    socketExpression = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Socket attribute.";
        type = types.socketKey;
      };
    };
    osfExpression = submodule' {
      options.key = lib.mkOption {
        description = "Which part of the fingerprint info to match against. At this point, only the OS name is supported.";
        type = types.osfKey;
      };
      options.ttl = mkNullOption {
        description = lib.mdDoc "Define how the packet’s TTL value is to be matched. This property is optional. If omitted, the TTL value has to match exactly. A value of **loose** accepts TTL values less than the fingerprint one. A value of **skip** omits TTL value comparison entirely.";
        type = types.osfTtl;
      };
    };
    dccpOption = submodule' {
      options.type = lib.mkOption {
        description = "DCCP option type.";
        type = lib.types.ints.u8;
      };
    };
    dslExprHackType = submodule' {
      skipNulls = false;
      finalMerge = x: x.__expr__;
      freeformType = lib.types.unspecified;
      options.__expr__ = lib.mkOption {
        type = types.expression;
      };
    };
    expression' = attrs: oneOf' ({
      name = "nftablesExpression";
      description = "nftables expression";
      types = [ lib.types.int lib.types.bool (lib.types.listOf types.expression) stringLike types.dslExprHackType ] ++ (lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} expression.\n\n${v.description}";
      })) {
        concat = {
          type = lib.types.listOf types.expression;
          description = "Concatenate several expressions.";
        };
        set = {
          type = types.expression;
          description = "This object constructs an anonymous set. For mappings, an array of arrays with exactly two elements is expected.";
        };
        map = {
          type = types.mapExpression;
          description = "Mapping expression consisting of value/target pairs.";
        };
        prefix = {
          type = types.prefixExpression;
          description = lib.mdDoc "Construct an IPv4 or IPv6 prefix consisting of address part in **addr** and prefix length in **len**.";
        };
        range = {
          type = types.rangeExpression;
          description = "Construct a range of values. The first array item denotes the lower boundary, the second one the upper boundary.";
        };
        payload = {
          type = types.payloadExpression;
          description = lib.mdDoc ''
            Construct a payload expression, i.e. a reference to a certain part of packet data. The first form creates a raw payload expression to point at a number (**len**) of bytes at a certain offset (**offset**) from a given reference point (**base**). The following base values are accepted:

            - **"ll"** - The offset is relative to Link Layer header start offset.
            - **"nh"** - The offset is relative to Network Layer header start offset.
            - **"th"** - The offset is relative to Transport Layer header start offset.

            The second form allows one to reference a field by name (**field**) in a named packet header (**protocol**).
          '';
        };
        exthdr = {
          type = types.exthdrExpression;
          description = lib.mdDoc ''
            Create a reference to a field (**field**) in an IPv6 extension header (**name**). **offset** is used only for **rt0** protocol.

            If the **field** property is not given, the expression is to be used as a header existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
        "tcp option" = {
          type = types.tcpOptionExpression;
          description = lib.mdDoc ''
            Create a reference to a field (**field**) of a TCP option header (**name**).

            If the **field** property is not given, the expression is to be used as a TCP option existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
        "ip option" = {
          type = types.ipOptionExpression;
          description = "This isn't documented upstream";
        };
        "sctp chunk" = {
          type = types.sctpChunkExpression;
          description = ''
            Create a reference to a field (**field**) of an SCTP chunk (name).

            If the **field** property is not given, the expression is to be used as an SCTP chunk existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
        meta = {
          type = types.metaExpression;
          description = "Create a reference to packet meta data.";
        };
        rt = {
          type = types.rtExpression;
          description = lib.mdDoc ''
            Create a reference to packet routing data.

            The **family** property is optional and defaults to unspecified.
          '';
        };
        ct = {
          type = types.ctExpression;
          description = lib.mdDoc ''
            Create a reference to packet conntrack data.

            Some CT keys do not support a direction. In this case, **dir** must not be given.
          '';
        };
        numgen = {
          type = types.numgenExpression;
          description = lib.mdDoc ''
            Create a number generator.

            The **offset** property is optional and defaults to 0.
          '';
        };
        jhash = {
          type = types.jhashExpression;
          description = "Hash packet data (Jenkins Hash).";
        };
        symhash = {
          type = types.symhashExpression;
          description = "Hash packet data (Symmetric Hash).";
        };
        fib = {
          type = types.fibExpression;
          description = "Perform kernel Forwarding Information Base lookups.";
        };
        "|" = {
          type = types.binOpExpression;
          description = "Binary or.";
        };
        "^" = {
          type = types.binOpExpression;
          description = "Binary xor.";
        };
        "&" = {
          type = types.binOpExpression;
          description = "Binary and.";
        };
        "<<" = {
          type = types.binOpExpression;
          description = "Left shift.";
        };
        ">>" = {
          type = types.binOpExpression;
          description = "Right shift.";
        };
        accept = {
          type = types.null;
          description = lib.mdDoc "Same as the **accept** statement, but for use in verdict maps.";
        };
        drop = {
          type = types.null;
          description = lib.mdDoc "Same as the **drop** statement, but for use in verdict maps.";
        };
        continue = {
          type = types.null;
          description = lib.mdDoc "Same as the **continue** statement, but for use in verdict maps.";
        };
        return = {
          type = types.null;
          description = lib.mdDoc "Same as the **return** statement, but for use in verdict maps.";
        };
        jump = {
          type = types.jumpExpression;
          description = lib.mdDoc "Same as the **jump** statement, but for use in verdict maps.";
        };
        goto = {
          type = types.gotoExpression;
          description = lib.mdDoc "Same as the **goto** statement, but for use in verdict maps.";
        };
        elem = {
          type = types.elemExpression;
          description = lib.mdDoc "Explicitly set element object, in case **timeout**, **expires** or **comment** are desired. Otherwise, it may be replaced by the value of **val**.";
        };
        socket = {
          type = types.socketExpression;
          description = "Construct a reference to packet’s socket.";
        };
        osf = {
          type = types.osfExpression;
          description = "";
        };
        ipsec = {
          type = types.ipsecExpression;
          description = "Undocumented upstream";
        };
        "dccp option" = {
          type = types.dccpOption;
          description = lib.mdDoc ''
            Create a reference to a DCCP option (**type**).

            The expression is to be used as a DCCP option existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
      });
    } // attrs);
    expression = types.expression' {};
  };
  # this is a function that takes a enum name and enum attrs (key = enum element, val = enum element info)
  # and for each enum element sets __enumName__ to enum name, __enum__ to enum itself, __value__ to element name,
  # __toString to a func that returns the element name, and takes enum's attrs for the rest
  mkEnum = name: attrs: let self = builtins.mapAttrs (k: v: (v // {
    __enumName__ = name;
    # __enum__ = self;
    __value__ = k;
    __toString = self: k;
  })) attrs; in self;
  nftTypes = mkEnum "nftTypes" {
    invalid.description = "invalid";
    verdict.description = "netfilter verdict";
    nf_proto = { description = "netfilter protocol"; enum = nfProtos; bits = 8; };
    bitmask = { description = "bitmask"; __functor = self: bits: self // { inherit bits; }; };
    integer = { description = "integer"; __functor = self: bits: self // { inherit bits; }; };
    string.description = "string";
    ll_addr.description = "link layer address";
    ipv4_addr.bits = 32;
    ipv4_addr.description = "IPv4 address";
    ipv4_addr.check = x: builtins.isString x && (let spl = builtins.split "." x; in
        builtins.length spl == 7
        && builtins.all lib.id (lib.imap0 (i: x:
          if i / 2 * 2 == i
          then builtins.isString x && builtins.match "25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]" x
          else x == []) spl));
    ipv6_addr.bits = 128;
    ipv6_addr.description = "IPv6 address";
    ipv6_addr.check = x: let
      spl = builtins.split "::" x;
      chk = if !(builtins.isString x) then 999 else let spl = builtins.split ":" x; in
        if (builtins.length spl) / 2 * 2 != builtins.length spl && builtins.all lib.id (lib.imap0 (i: x:
          if i / 2 * 2 == i
          then builtins.isString x && builtins.match "[0-9a-f]?[0-9a-f]?[0-9a-f]?[0-9a-f]" x
          else x == []) spl)
        then (builtins.length spl + 1) / 2 else 999;
    in
      if builtins.length spl == 1 then chk x == 8
      else builtins.length spl == 3 && builtins.elemAt spl 1 == [] && (chk (builtins.head spl)) + (chk (lib.last spl)) < 8;
    ether_addr.bits = 48;
    ether_addr.description = "Ethernet address";
    ether_addr.check = x:
      builtins.isString x && (let spl = builtins.split ":" x; in
        builtins.length spl == 11
        && builtins.all lib.id (lib.imap0 (i: x:
            if i / 2 * 2 == i
            then builtins.isString x && builtins.match "[0-9a-f][0-9a-f]" x
            else x == [])
          spl));
    ether_type = { bits = 16; description = "Ethernet protocol"; enum = etherTypes; };
    arp_op = { bits = 16; description = "ARP operation"; enum = arpOps; };
    inet_proto = { bits = 8; description = "Internet protocol"; enum = inetProtos'; };
    inet_service = { bits = 16; description = "internet network service"; }; # port
    icmp_type = { bits = 8; description = "ICMP type"; enum = icmpTypes; };
    tcp_flag = { bits = 8; description = "TCP flag"; enum = tcpFlags; };
    dccp_pkttype = { bits = 4; description = "DCCP packet type"; enum = dccpPktTypes; };
    mh_type = { bits = 8; description = "Mobility Header Type"; enum = mhTypes; };
    mark = { bits = 32; description = "packet mark"; };
    iface_index = { bits = 32; description = "network interface index"; };
    iface_type = { bits = 16; description = "network interface type"; enum = ifaceTypes; };
    realm = { bits = 32; description = "routing realm"; };
    classid = { bits = 32; description = "TC classid"; };
    uid = { bits = 32; description = "user ID"; };
    gid = { bits = 32; description = "group ID"; };
    ct_state = { bits = 32; description = "conntrack state"; enum = ctStates; };
    ct_dir = { bits = 8; description = "conntrack direction"; enum = ctDirs; };
    ct_status = { bits = 32; description = "conntrack status"; enum = ctStatuses; };
    icmpv6_type = { bits = 8; description = "ICMPv6 type"; enum = icmpv6Types; };
    pkt_type = { bits = 8; description = "packet type"; enum = pktTypes; };
    icmp_code = { bits = 8; description = "icmp code"; enum = icmpCodes; };
    icmpv6_code = { bits = 8; description = "icmpv6 code"; enum = icmpv6Codes; };
    icmpx_code = { bits = 8; description = "icmpx code"; enum = icmpxCodes; };
    devgroup = { bits = 32; description = "devgroup name"; };
    dscp = { bits = 6; description = "Differentiated Services Code Point"; enum = dscpTypes; };
    ecn.enum = { bits = 2; description = "Explicit Congestion Notification"; enum = ecnTypes; };
    fib_addrtype = { bits = 32; description = "fib address type"; enum = fibAddrTypes; };
    boolean = { bits = 1; description = "boolean type"; enum = booleans; };
    ifname = { bits = 128; description = "network interface name"; }; # string
    igmp_type = { bits = 8; description = "IGMP type"; enum = igmpTypes; };
    time = { bits = 64; description = "Relative time of packet reception"; };
    hour = { bits = 32; description = "Hour of day of packet reception"; };
    day = { bits = 8; description = "Day of week of packet reception"; enum = days; };
    cgroupsv2 = { bits = 64; description = "cgroupsv2 path"; };
    # special cases: those types are hardcoded in parser_json.c/string_to_nft_object and can only be set values
    # the reason is they are "objects" rather than "built-in types"
    counter.isKey = false;
    quota.isKey = false;
    limit.isKey = false;
    secmark.isKey = false;
  };
  setKeyTypes = lib.filterAttrs (k: v: v.isKey or true) nftTypes;
  xtTypes = mkEnum "xtTypes" {
    match = {};
    target = {};
    watcher = {};
  };
  # src/proto.c, proto_base_tokens
  payloadBases = mkEnum "payloadBases" {
    ll = {}; # link layer
    nh = {}; # network layer
    th = {}; # transport layer
    ih = {}; # inner/payload data
  };
  rtKeys = mkEnum "rtKeys" {
    classid = {};
    nexthop = {};
    mtu = {};
    ipsec = {};
  };
  ctDirs = mkEnum "ctDirs" {
    original = {};
    reply = {};
  };
  ngModes = mkEnum "ngModes" {
    inc = {};
    random = {};
  };
  fibResults = mkEnum "fibResults" {
    # get output interface id
    oif = {};
    # get output interface name
    oifname = {};
    # get output address type
    type = {};
  };
  fibFlags = mkEnum "fibFlags" {
    saddr = {};
    daddr = {};
    mark = {};
    iif = {};
    oif = {};
  };
  socketKeys = mkEnum "socketKeys" {
    transparent = {};
    mark = {};
    wildcard = {};
  };
  osfKeys = mkEnum "osfKeys" {
    name = {};
    # undocumented
    version = {};
  };
  osfTtls = mkEnum "osfTtl" {
    loose = {};
    skip = {};
  };
  # if type info is needed, it can be parsed from src/meta.c (const struct meta_template meta_templates[])
  metaKeys = with nftTypes; let self = mkEnum "metaKeys" {
    # "unqualified" means "don't have to write `meta` before the meta key"
    # but it can mean different things
    # first, the parser is quite lax:
    # length | nfproto | l4proto | protocol | priority are qualified
    # mark | iif | iifname | iiftype | oif | oifname | oiftype | skuid | skgid | nftrace | rtclassid | ibrname | obrname | pkttype | cpu | iifgroup | oifgroup | cgroup | random | ipsec | iifkind | oifkind | time | hour | day are unqualified
    # however!
    # when dumping the output back to the user, a different definition of "unqualified" is used.
    # in that case, only iif/oif/iifname/oifname/iifgroup/oifgroup are considered unqualified
    # with that in mind:
    # the keys that MUST be preceded by "meta " in *input* are marked as qualified
    # the keys that MUST NOT be preceded by "meta " in *output* are marked as unqualified
    # the rest dont have anything set, which means they are unqualified in input, but qualified in output
    length = { qualified = true; type = integer 32; };
    protocol = { qualified = true; type = ether_type; };
    nfproto.type = nf_proto;
    l4proto.type = inet_proto;
    priority = { qualified = true; type = classid; };
    mark.type = mark;
    iif = { unqualified = true; type = iface_index; };
    iifname = { unqualified = true; type = ifname; };
    iiftype.type = iface_type;
    oif = { unqualified = true; type = iface_index; };
    oifname = { unqualified = true; type = ifname; };
    oiftype.type = iface_type;
    skuid.type = uid;
    skgid.type = gid;
    nftrace.type = boolean; # integer 1;
    rtclassid.type = realm;
    ibrname.type = ifname;
    obrname.type = ifname;
    pkttype.type = pkt_type;
    cpu.type = integer 32;
    iifgroup = { unqualified = true; type = devgroup; };
    oifgroup = { unqualified = true; type = devgroup; };
    cgroup.type = integer 32;
    random = { qualified = true; type = integer 32; };
    ipsec.type = boolean;
    iifkind.type = ifname;
    oifkind.type = ifname;
    ibrpvid.type = integer 16; # iifpvid
    ibrvproto.type = ether_type; # iifvproto
    time.type = time;
    day.type = day;
    hour.type = hour;
    secmark = { qualified = true; type = integer 32; };
    sdif.type = iface_index;
    sdifname.type = ifname;
    broute.type = boolean; # integer 1;
  }; in self // {
    # technically those aliases are supported by nftables code, but if they are aliases anyway
    # i might as well make them proper aliases in nix code as well
    ibriport = self.iifname;
    obriport = self.oifname;
    secpath = self.ipsec;
    # the following two aren't actually supported by the code but instead documented by the wrong names...
    ibridgename = self.ibrname;
    obridgename = self.obrname;
  };
  nfProtos = mkEnum "nf_proto" {
    ipv4.value = 2;
    ipv6.value = 10;
  };
  families = mkEnum "families" {
    ip = {
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" ];
      isIp = true;
      isL3 = true;
    };
    ip6 = {
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" ];
      isIp = true;
      isL3 = true;
    };
    inet = {
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" "ingress" ];
      isL3 = true;
    };
    arp = {
      hooks = [ "input" "output" ];
      isL3 = true;
    };
    bridge = {
      # not sure if ingress is supported here, docs dont specify it, whatever
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" "ingress" ];
    };
    netdev = {
      hooks = [ "ingress" "egress" ];
      requireBaseChainDevice = true;
    };
  };
  ipFamilies = lib.filterAttrs (k: v: v.isIp or false) families;
  l3Families = lib.filterAttrs (k: v: v.isL3 or false) families;
  chainPolicies = mkEnum "chainPolicies" {
    accept = {};
    drop = {};
  };
  setPolicies = mkEnum "setPolicies" {
    performance = {};
    memory = {};
  };
  setFlags = mkEnum "setFlags" {
    constant = {};
    dynamic = {};
    interval = {};
    timeout = {};
  };
  natFlags = mkEnum "natFlags" {
    random = {};
    fully-random = {};
    persistent = {};
    netmap = {};
  };
  natTypeFlags = mkEnum "natTypeFlags" {
    interval = {};
    prefix = {};
    concat = {};
  };
  queueFlags = mkEnum "queueFlags" {
    bypass = {};
    fanout = {};
  };
  logLevels = mkEnum "logLevels" {
    emerg = {};
    alert = {};
    crit = {};
    err = {};
    warn = {};
    notice = {};
    info = {};
    debug = {};
    audit = {};
  };
  logFlags' = mkEnum "logFlags" {
    "tcp sequence" = {};
    "tcp options" = {};
    "ip options" = {};
    skuid = {};
    ether = {};
    all = {};
  };
  logFlags = logFlags' // {
    tcpSequence = logFlags'."tcp sequence";
    tcpOptions = logFlags'."tcp options";
    ipOptions = logFlags'."ip options";
  };
  chainTypes = mkEnum "chainTypes" {
    # Standard chain type to use when in doubt.
    filter = { };
    # Chains of this type perform Native Address Translation based on conntrack entries.
    # Only the first packet of a connection actually traverses this chain - its rules
    # usually define details of the created conntrack entry (NAT statements for instance). 
    nat = {
      families = [ "ip" "ip6" "inet" ];
      hooks = [ "prerouting" "input" "output" "postrouting" ];
    };
    # If a packet has traversed a chain of this type and is about to be accepted, a new
    # route lookup is performed if relevant parts of the IP header have changed. This
    # allows one to e.g. implement policy routing selectors in nftables.
    route = {
      families = [ "ip" "ip6" ];
      hooks = [ "output" ];
    };
  };
  hooks = mkEnum "hooks" {
    prerouting = {};
    input = {};
    forward = {};
    output = {};
    postrouting = {};
    ingress = {};
  };
  ctProtocols = mkEnum "ctProtocols" {
    tcp = { };
    udp = { };
    # documented but not actually supported
    # dccp = {};
    # sctp = {};
    # gre = {};
    # icmpv6 = {};
    # icmp = {};
    # generic = {};
  };
  timeUnits = mkEnum "timeUnits" {
    second = {};
    minute = {};
    hour = {};
    day = {};
    week = {};
  };
  rateUnits = mkEnum "byteUnits" {
    bytes = {};
    kbytes = {};
    mbytes = {};
    packets = { onlyRate = true; };
  };
  byteUnits = lib.filterAttrs (k: v: !(v.onlyRate or false)) rateUnits;
  rejectTypes' = mkEnum "rejectTypes" {
    icmpx = { };
    icmp = { };
    icmpv6 = { };
    "tcp reset" = { };
  };
  rejectTypes = rejectTypes' // {
    tcpReset = rejectTypes'."tcp reset";
  };
  setOps = mkEnum "setOps" {
    add = {};
    update = {};
    delete = {};
  };
  synproxyFlags = mkEnum "synproxyFlags" {
    timestamp = { };
    sack-perm = { };
  };
  payloadProtocols = with nftTypes; mkEnum "payloadProtocols" {
    ether.fields = {
      daddr = ether_addr;
      saddr = ether_addr;
      type = ether_type;
    };
    vlan.fields = {
      pcp = integer 3;
      # dei is the same as cfi
      dei = integer 1;
      cfi = integer 1;
      id = integer 12;
      type = ether_type;
    };
    arp.fields = {
      htype = integer 16;
      ptype = ether_type;
      hlen = integer 8;
      plen = integer 8;
      operation = arp_op;
      "saddr ip" = ipv4_addr;
      "saddr ether" = ether_addr;
      "daddr ip" = ipv4_addr;
      "daddr ether" = ether_addr;
    };
    ip.fields = {
      l4proto = inet_proto; # not sure if this is valid?
      version = integer 4;
      hdrlength = integer 4;
      inherit dscp ecn;
      length = integer 16;
      id = integer 16;
      frag-off = integer 16;
      ttl = integer 8;
      protocol = inet_proto;
      checksum = integer 16;
      saddr = ipv4_addr;
      daddr = ipv4_addr;
    };
    icmp.fields = {
      type = icmp_type;
      code = icmp_code;
      checksum = integer 16;
      id = integer 16;
      sequence = integer 16;
      gateway = integer 32;
      mtu = integer 16;
    };
    igmp.fields = {
      type = igmp_type;
      mrt = integer 8;
      checksum = integer 16;
      group = integer 32;
    };
    ip6.fields = {
      l4proto = inet_proto; # not sure if this is valid?
      version = integer 4;
      dscp = integer 6;
      ecn = integer 2;
      flowlabel = integer 20;
      length = integer 16;
      nexthdr = inet_proto;
      hoplimit = integer 8;
      saddr = ipv6_addr;
      daddr = ipv6_addr;
    };
    # documentation shows packet-too-big instead of mtu... but in the code and in the internal tests it's clearly mtu...
    icmpv6.fields = {
      type = icmpv6_type;
      code = icmpv6_code;
      checksum = integer 16;
      parameter-problem = integer 32;
      mtu = integer 32;
      id = integer 16;
      sequence = integer 16;
      max-delay = integer 16;
    };
    tcp.fields = {
      sport = inet_service;
      dport = inet_service;
      sequence = integer 32;
      ackseq = integer 32;
      doff = integer 4;
      reserved = integer 4;
      flags = tcp_flag;
      window = integer 16;
      checksum = integer 16;
      urgptr = integer 16;
    };
    udp.fields = {
      sport = inet_service;
      dport = inet_service;
      length = integer 16;
      checksum = integer 16;
    };
    udplite.fields = {
      sport = inet_service;
      dport = inet_service;
      csumcov = integer 16;
      checksum = integer 16;
    };
    sctp.fields = {
      sport = inet_service;
      dport = inet_service;
      vtag = integer 32;
      checksum = integer 32;
    };
    dccp.fields = {
      sport = inet_service;
      dport = inet_service;
      type = dccp_pkttype;
    };
    ah.fields = {
      nexthdr = inet_proto;
      hdrlength = integer 8;
      reserved = integer 16;
      spi = integer 32;
      sequence = integer 32;
    };
    esp.fields = {
      spi = integer 32;
      sequence = integer 32;
    };
    comp.fields = {
      nexthdr = inet_proto;
      flags = integer 8;
      cpi = integer 16;
    };
    # this isn't documented anywhere, but yes it works
    th.fields = {
      sport = inet_service;
      dport = inet_service;
    };
    # the following protocols encapsulate other protocols
    # getting encapsulated protos' fields isn't supported in the json syntax, and as such the protocols aren't supported altogether
    # to add insult to the injury, the docs specify wrong fields... well, it's fine, because the protocols aren't supported anyway
    #gre.fields = [ "flags" "version" "protocol" ];
    # code shows vni, type but docs show vni, flags...
    #geneve.fields = [ "vni" "type" ];
    # code shows no fields, docs show vni, flags
    #gretap.fields = [ ];
    # this is fine, finally something docs agree on
    #vxlan.fields = [ "vni" "flags" ];
  };
  payloadFields = mkEnum "payloadFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: builtins.attrNames x.fields)
        (builtins.attrValues payloadProtocols))));
  exthdrs = with nftTypes; mkEnum "exthdrs" {
    hbh.fields = {
      nexthdr = inet_proto;
      hdrlength = integer 8;
    };
    rt2.fields = { };
    rt0.fields = { 
      reserved = integer 32;
      "addr[1]" = ipv6_addr;
      "addr[2]" = ipv6_addr;
    };
    # i'm beginning to think I shouldn't trust these docs...
    srh.fields = {
      last-entry = integer 8;
      flags = integer 8;
      tag = integer 16;
      "sid[1]" = ipv6_addr;
      "sid[2]" = ipv6_addr;
    };
    # srh.fields = [ "last-entry" "flags" "tag" "sid" "seg-left" ];
    rt.fields = {
      nexthdr = inet_proto;
      hdrlength = integer 8;
      type = integer 8;
      seg-left = integer 8;
    };
    frag.fields = {
      nexthdr = inet_proto;
      reserved = integer 8;
      frag-off = integer 13;
      reserved2 = integer 2;
      # more-fragments = integer 1;
      more-fragments = boolean;
      id = integer 16;
    };
    dst.fields = {
      nexthdr = inet_proto;
      hdrlength = integer 8;
    };
    mh.fields = {
      nexthdr = inet_proto;
      hdrlength = integer 8;
      type = mh_type;
      reserved = integer 8;
      checksum = integer 16;
    };
  };
  exthdrFields = mkEnum "exthdrFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: builtins.attrNames x.fields)
        (builtins.attrValues exthdrs))));
  # src/tcpopt.c, special case in parser for sack0-sack3
  tcpOptions = with nftTypes; let
    length = integer 8;
    size = integer 16;
    count = integer 8;
    left = integer 32;
    right = integer 32;
    tsval = integer 32;
    tsecr = integer 32;
    subtype = integer 4;
  in mkEnum "tcpOptions" {
    # additionally, "kind" is listed everywhere in the code... just in case, don't support it here
    eol.fields = { };
    nop.fields = { };
    maxseg.fields = { inherit length size; };
    window.fields = { inherit length count; };
    sack-perm.fields = { inherit length; };
    sack.fields = { inherit length left right; };
    sack0.fields = { inherit length left right; };
    sack1.fields = { inherit length left right; };
    sack2.fields = { inherit length left right; };
    sack3.fields = { inherit length left right; };
    timestamp.fields = { inherit length tsval tsecr; };
    # undocumented
    fastopen.fields = { inherit length; };
    md5sig.fields = { inherit length; };
    mptcp.fields = { inherit length subtype; };
  };
  tcpOptionFields = mkEnum "tcpOptionFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: builtins.attrNames x.fields)
        (builtins.attrValues tcpOptions))));
  ipOptions = with nftTypes; let
    type = integer 8;
    length = integer 8;
    ptr = integer 8;
    addr = integer 32;
    value = integer 16;
  in mkEnum "ipOptions" {
    lsrr.fields = { inherit type length ptr addr; };
    rr.fields = { inherit type length ptr addr; };
    ssrr.fields = { inherit type length ptr addr; };
    ra.fields = { inherit type length value; };
  };
  ipOptionFields = mkEnum "ipOptionFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: builtins.attrNames x.fields)
        (builtins.attrValues ipOptions))));
  # src/sctp_chunk.c
  sctpChunks = with nftTypes; let
    type = integer 8;
    flags = integer 8;
    length = integer 16;
    tsn = integer 32;
    stream = integer 16;
    ssn = integer 16;
    ppid = integer 32;
    init-tag = integer 32;
    a-rwnd = integer 32;
    num-outbound-streams = integer 16;
    num-inbound-streams = integer 16;
    cum-tsn-ack = integer 32;
    num-gap-ack-blocks = integer 16;
    num-dup-tsns = integer 16;
    initial-tsn = integer 32;
    lowest-tsn = integer 32;
    seqno = integer 32;
    new-cum-tsn = integer 32;
  in mkEnum "sctpChunks" {
    data.fields = { inherit type flags length tsn stream ssn ppid; };
    init.fields = { inherit type flags length init-tag a-rwnd num-outbound-streams num-inbound-streams initial-tsn; };
    init-ack.fields = { inherit type flags length init-tag a-rwnd num-outbound-streams num-inbound-streams initial-tsn; };
    sack.fields = { inherit type flags length a-rwnd cum-tsn-ack num-gap-ack-blocks num-dup-tsns; };
    heartbeat.fields = { inherit type flags length; };
    heartbeat-ack.fields = { inherit type flags length; };
    abort.fields = { inherit type flags length; };
    shutdown.fields = { inherit type flags length cum-tsn-ack; };
    shutdown-ack.fields = { inherit type flags length; };
    error.fields = { inherit type flags length; };
    cookie-echo.fields = { inherit type flags length; };
    cookie-ack.fields = { inherit type flags length; };
    ecne.fields = { inherit type flags length lowest-tsn; };
    cwr.fields = { inherit type flags length lowest-tsn; };
    shutdown-complete.fields = { inherit type flags length; };
    asconf-ack.fields = { inherit type flags length seqno; };
    forward-tsn.fields = { inherit type flags length new-cum-tsn; };
    asconf.fields = { inherit type flags length seqno; };
  };
  sctpChunkFields = mkEnum "sctpChunkFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: builtins.attrNames x.fields)
        (builtins.attrValues sctpChunks))));
  ctKeys = let
    ff = { dir = false; family = false; }; # false/false
    nf = ff // { dir = null; }; # null/false
    tf = ff // { dir = true; }; # etc
    tt = tf // { family = true; };
  in mkEnum "ctKeys" {
    state = ff;
    direction = ff;
    status = ff;
    mark = ff;
    expiration = ff;
    helper = ff;
    l3proto = nf;
    saddr = tt;
    daddr = tt;
    protocol = nf;
    proto-src = tf;
    proto-dst = tf;
    label = ff;
    bytes = nf;
    packets = nf;
    avgpkt = nf;
    zone = nf;
    event = ff; # undocumented
    "ip saddr" = nf; # undocumented
    "ip daddr" = nf; # undocumented
    "ip6 saddr" = nf; # undocumented
    "ip6 daddr" = nf; # undocumented
    secmark = ff; # undocumented

    # count = ff; - ? apparently documented but not supported
    id = ff;
  };
  operators' = mkEnum "operators" {
    # documented as supported, but probably doesn't make much sense
    # (this is for the match *statement*)
    # "&" = { };
    # "|" = { };
    # "^" = { };
    # "<<" = { };
    # ">>" = { };
    "==" = { };
    "!=" = { };
    "<" = { };
    ">" = { };
    "<=" = { };
    ">=" = { };
    # bitmask
    "in" = { };
  };
  operators = operators' // {
    # create some aliases
    # and = operators'."&";
    # or = operators'."|";
    # xor = operators'."^";
    # lsh = operators'."<<";
    # rsh = operators'.">>";
    eq = operators'."==";
    ne = operators'."!=";
    lt = operators'."<";
    gt = operators'.">";
    le = operators'."<=";
    ge = operators'.">=";
    # IN = operators'."in";
    # in' = operators'."in";
    auto = operators."in";
    au = operators."in";
    implicit = operators'."in";
  };
  flowtableOps = mkEnum "flowOps" {
    add = { };
  };
  ipsecDirs = mkEnum "ipsecDirs" {
    "in" = { };
    out = { };
  };
  ipsecKeys = mkEnum "ipsecKeys" {
    # basically, family is only actually used in daddr/saddr
    daddr.needsFamily = true;
    saddr.needsFamily = true;
    reqid.needsFamily = false;
    spi.needsFamily = false;
  };
  flowtablePriorities = mkEnum "flowtablePriorities" {
    filter.value = 0;
  };
  chainPriorities = mkEnum "chainPriorities" {
    raw = {
      value = family: -300;
      families = [ "ip" "ip6" "inet" ];
    };
    mangle = {
      value = family: -150;
      families = [ "ip" "ip6" "inet" ];
    };
    dstnat = {
      value = family: if family == "bridge" then -300 else -100;
      families = [ "ip" "ip6" "inet" "bridge" ];
      hooks = [ "prerouting" ];
    };
    filter = {
      value = family: if family == "bridge" then -200 else 0;
      families = [ "ip" "ip6" "inet" "arp" "netdev" "bridge" ];
    };
    security = {
      value = family: 50;
      families = [ "ip" "ip6" "inet" ];
    };
    srcnat = {
      value = family: if family == "bridge" then 300 else 100;
      families = [ "ip" "ip6" "inet" "bridge" ];
      hooks = [ "postrouting" ];
    };
    out = {
      value = family: 100;
      families = [ "bridge" ];
    };
  };
  # tcp_flag
  tcpFlags = mkEnum "tcp_flag" {
    fin.value = 1;
    syn.value = 2;
    rst.value = 4;
    psh.value = 8;
    ack.value = 16;
    urg.value = 32;
    ecn.value = 64;
    cwr.value = 128;
  };
  # fib_addrtype
  fibAddrTypes = mkEnum "fib_addrtype" {
    unspec.value = 0;
    unicast.value = 1;
    local.value = 2;
    broadcast.value = 3;
    anycast.value = 4;
    multicast.value = 5;
    blackhole.value = 6;
    unreachable.value = 7;
    prohibit.value = 8;
  };
  # icmp_type; for payload
  icmpTypes = mkEnum "icmp_type" {
    echo-reply.value = 0;
    destination-unreachable.value = 3;
    source-quench.value = 4;
    redirect.value = 5;
    echo-request.value = 8;
    router-advertisement.value = 9;
    router-solicitation.value = 10;
    time-exceeded.value = 11;
    parameter-problem.value = 12;
    timestamp-request.value = 13;
    timestamp-reply.value = 14;
    info-request.value = 15;
    info-reply.value = 16;
    address-mask-request.value = 17;
    address-mask-reply.value = 18;
  };
  # for payload
  icmpv6Types = mkEnum "icmpv6_type" {
    destination-unreachable.value = 1;
    packet-too-big.value = 2;
    time-exceeded.value = 3;
    parameter-problem.value = 4;
    echo-request.value = 128;
    echo-reply.value = 129;
    mld-listener-query.value = 130;
    mld-listener-report.value = 131;
    mld-listener-done.value = 132;
    mld-listener-reduction.value = 132;
    nd-router-solicit.value = 133;
    nd-router-advert.value = 134;
    nd-neighbor-solicit.value = 135;
    nd-neighbor-advert.value = 136;
    nd-redirect.value = 137;
    router-renumbering.value = 138;
    ind-neighbor-solicit.value = 141;
    ind-neighbor-advert.value = 142;
    mld2-listener-report.value = 143;
  };
  # for payload
  igmpTypes = mkEnum "igmp_type" {
    membership-query.value = 17;
    membership-report-v1.value = 18;
    membership-report-v2.value = 22;
    membership-report-v3.value = 34;
    leave-group.value = 23;
  };
  # for dccp payload
  dccpPktTypes = mkEnum "dccp_pkttype" {
    request.value = 0;
    response.value = 1;
    data.value = 2;
    ack.value = 3;
    dataack.value = 4;
    closereq.value = 5;
    close.value = 6;
    reset.value = 7;
    sync.value = 8;
    syncack.value = 9;
  };
  # for ip payload. The nftables type is just called "dscp"
  dscpTypes = mkEnum "dscp" {
    cs0.value = 0;
    cs1.value = 8;
    cs2.value = 16;
    cs3.value = 24;
    cs4.value = 32;
    cs5.value = 40;
    cs6.value = 48;
    cs7.value = 56;
    df.value = 0;
    be.value = 0;
    lephb.value = 1;
    af11.value = 10;
    af12.value = 12;
    af13.value = 14;
    af21.value = 18;
    af22.value = 20;
    af23.value = 22;
    af31.value = 26;
    af32.value = 28;
    af33.value = 30;
    af41.value = 34;
    af42.value = 36;
    af43.value = 38;
    va.value = 44;
    ef.value = 46;
  };
  # for ip payload. The nftables type is just called "ecn"
  ecnTypes = mkEnum "ecn" {
    not-ect.value = 0;
    ect1.value = 1;
    ect0.value = 2;
    ce.value = 3;
  };
  ctStates = mkEnum "ct_state" {
    invalid.value = 1;
    established.value = 2;
    related.value = 4;
    new.value = 8;
    untracked.value = 64;
  };
  # mobility header exthdr
  mhTypes = mkEnum "mh_type" {
    binding-refresh-request.value = 0;
    home-test-init.value = 1;
    careof-test-init.value = 2;
    home-test.value = 3;
    careof-test.value = 4;
    binding-update.value = 5;
    binding-acknowledgement.value = 6;
    binding-error.value = 7;
    fast-binding-update.value = 8;
    fast-binding-acknowledgement.value = 9;
    fast-binding-advertisement.value = 10;
    experimental-mobility-header.value = 11;
    home-agent-switch-message.value = 12;
  };
  # inet_proto, the type of meta ip protocol/meta ip6 nexthdr/etc
  inetProtos' = mkEnum "inet_proto" {
    hopopt.value = 0;
    icmp.value = 1;
    igmp.value = 2;
    ggp.value = 3;
    ipv4.value = 4;
    st.value = 5;
    tcp.value = 6;
    cbt.value = 7;
    egp.value = 8;
    igp.value = 9;
    bbn-rcc-mon.value = 10;
    nvp-ii.value = 11;
    pup.value = 12;
    emcon.value = 14;
    xnet.value = 15;
    chaos.value = 16;
    udp.value = 17;
    mux.value = 18;
    dcn-meas.value = 19;
    hmp.value = 20;
    prm.value = 21;
    xns-idp.value = 22;
    trunk-1.value = 23;
    trunk-2.value = 24;
    leaf-1.value = 25;
    leaf-2.value = 26;
    rdp.value = 27;
    irtp.value = 28;
    iso-tp4.value = 29;
    netblt.value = 30;
    mfe-nsp.value = 31;
    merit-inp.value = 32;
    dccp.value = 33;
    "3pc".value = 34;
    idpr.value = 35;
    xtp.value = 36;
    ddp.value = 37;
    idpr-cmtp.value = 38;
    "tp++".value = 39;
    il.value = 40;
    ipv6.value = 41;
    sdrp.value = 42;
    ipv6-route.value = 43;
    ipv6-frag.value = 44;
    idrp.value = 45;
    rsvp.value = 46;
    gre.value = 47;
    dsr.value = 48;
    bna.value = 49;
    esp.value = 50;
    ah.value = 51;
    i-nlsp.value = 52;
    narp.value = 54;
    mobile.value = 55;
    tlsp.value = 56;
    skip.value = 57;
    ipv6-icmp.value = 58;
    ipv6-nonxt.value = 59;
    ipv6-opts.value = 60;
    cftp.value = 62;
    sat-expak.value = 64;
    kryptolan.value = 65;
    rvd.value = 66;
    ippc.value = 67;
    sat-mon.value = 69;
    visa.value = 70;
    ipcv.value = 71;
    cpnx.value = 72;
    cphb.value = 73;
    wsn.value = 74;
    pvp.value = 75;
    br-sat-mon.value = 76;
    sun-nd.value = 77;
    wb-mon.value = 78;
    wb-expak.value = 79;
    iso-ip.value = 80;
    vmtp.value = 81;
    secure-vmtp.value = 82;
    vines.value = 83;
    iptm.value = 84;
    nsfnet-igp.value = 85;
    dgp.value = 86;
    tcf.value = 87;
    eigrp.value = 88;
    ospfigp.value = 89;
    sprite-rpc.value = 90;
    larp.value = 91;
    mtp.value = 92;
    "ax.25".value = 93;
    ipip.value = 94;
    scc-sp.value = 96;
    etherip.value = 97;
    encap.value = 98;
    gmtp.value = 100;
    ifmp.value = 101;
    pnni.value = 102;
    pim.value = 103;
    aris.value = 104;
    scps.value = 105;
    qnx.value = 106;
    "a/n".value = 107;
    ipcomp.value = 108;
    snp.value = 109;
    compaq-peer.value = 110;
    ipx-in-ip.value = 111;
    vrrp.value = 112;
    pgm.value = 113;
    l2tp.value = 115;
    ddx.value = 116;
    iatp.value = 117;
    stp.value = 118;
    srp.value = 119;
    uti.value = 120;
    smp.value = 121;
    ptp.value = 123;
    fire.value = 125;
    crtp.value = 126;
    crudp.value = 127;
    sscopmce.value = 128;
    iplt.value = 129;
    sps.value = 130;
    pipe.value = 131;
    sctp.value = 132;
    fc.value = 133;
    rsvp-e2e-ignore.value = 134;
    udplite.value = 136;
    mpls-in-ip.value = 137;
    manet.value = 138;
    hip.value = 139;
    shim6.value = 140;
    wesp.value = 141;
    rohc.value = 142;
    ethernet.value = 143;
    aggfrag.value = 144;
  };
  inetProtos = inetProtos' // {
    icmpv6 = inetProtos'.ipv6-icmp;
  };
  icmpCodes = mkEnum "icmp_code" {
    net-unreachable.value = 0;
    host-unreachable.value = 1;
    prot-unreachable.value = 2;
    port-unreachable.value = 3;
    net-prohibited.value = 9;
    host-prohibited.value = 10;
    admin-prohibited.value = 13;
    frag-needed.value = 4;
  };
  icmpv6Codes = mkEnum "icmpv6_code" {
    no-route.value = 0;
    admin-prohibited.value = 1;
    addr-unreachable.value = 3;
    port-unreachable.value = 4;
    policy-fail.value = 5;
    reject-route.value = 6;
  };
  icmpxCodes = mkEnum "icmpx_code" {
    port-unreachable.value = 1;
    admin-prohibited.value = 3;
    no-route.value = 0;
    host-unreachable.value = 2;
  };
  # special case: don't make this an actual enum
  booleans = {
    exists.value = true;
    missing.value = false;
  };
  exists = true;
  missing = false;
  etherTypes = mkEnum "ether_type" {
    ip.value = 8;
    arp.value = 1544;
    ip6.value = 56710;
    "8021q".value = 129;
    "8021ad".value = 43144;
    vlan.value = 129;
  };
  arpOps = mkEnum "arp_op" {
    request.value = 256;
    reply.value = 512;
    rrequest.value = 768;
    rreply.value = 1024;
    inrequest.value = 2048;
    inreply.value = 2304;
    nak.value = 2560;
  };
  ifaceTypes = mkEnum "iface_type" {
    ether.value = 1;
    ppp.value = 512;
    ipip.value = 768;
    ipip6.value = 769;
    loopback.value = 772;
    sit.value = 776;
    ipgre.value = 778;
  };
  ctStatuses = mkEnum "ct_status" {
    expected.value = 1;
    seen-reply.value = 2;
    assured.value = 4;
    confirmed.value = 8;
    snat.value = 16;
    dnat.value = 32;
    dying.value = 512;
  };
  pktTypes = mkEnum "pkt_type" {
    host.value = 0;
    unicast.value = 0;
    broadcast.value = 1;
    multicast.value = 2;
    other.value = 3;
  };
  days = mkEnum "day" {
    Sunday.value = 0;
    Monday.value = 1;
    Tuesday.value = 2;
    Wednesday.value = 3;
    Thursday.value = 4;
    Friday.value = 5;
    Saturday.value = 6;
  };
  connectionStates' = {
    close.proto = "tcp";
    close_wait.proto = "tcp";
    established.proto = "tcp";
    fin_wait.proto = "tcp";
    last_ack.proto = "tcp";
    retrans.proto = "tcp";
    syn_recv.proto = "tcp";
    syn_sent.proto = "tcp";
    time_wait.proto = "tcp";
    unack.proto = "tcp";
    replied.proto = "udp";
    unreplied.proto = "udp";
  };
  connectionStates = builtins.mapAttrs (k: v: k) connectionStates';
  tcpConnectionStates = builtins.mapAttrs (k: v: k) (lib.filterAttrs (k: v: v.proto == "tcp") connectionStates');
  udpConnectionStates = builtins.mapAttrs (k: v: k) (lib.filterAttrs (k: v: v.proto == "udp") connectionStates');

  notnft = {
    inherit
      arpOps booleans byteUnits chainPolicies chainPriorities chainTypes connectionStates ctDirs ctKeys ctProtocols ctStates ctStatuses
      days dccpPktTypes dscpTypes ecnTypes etherTypes exists exthdrFields exthdrs
      families fibAddrTypes fibFlags fibResults flowtablePriorities hooks
      icmpCodes icmpTypes icmpv6Codes icmpv6Types icmpxCodes ifaceTypes igmpTypes
      inetProtos ipFamilies ipOptionFields ipOptions ipsecDirs ipsecKeys isValidExpr
      logFlags logLevels metaKeys mhTypes missing
      natFlags natTypeFlags nfProtos nftTypes ngModes operators osfKeys osfTtls
      payloadBases payloadFields payloadProtocols pktTypes 
      queueFlags rateUnits rejectTypes rtKeys
      sctpChunkFields sctpChunks setFlags setKeyTypes setOps setPolicies socketKeys synproxyFlags
      tcpConnectionStates tcpFlags tcpOptionFields tcpOptions timeUnits types
      udpConnectionStates xtTypes;
    inherit exprEnums exprEnumsMerged exprEnumsRec innerExprs innerExprsRec mergeEnums mkEnum;
    dccpPkttypes = dccpPktTypes;
    # "days" isn't very descriptive, so here's an alias
    weekDays = days;
    dsl = import ./dsl.nix { inherit notnft; inherit lib; };
    inherit (import ./compile.nix { inherit notnft; inherit lib; })
      compileCmd compileExpr compileObject compileRuleset compileSetElem compileStmt compileStr;
  };
in rec {
  config = {
    _module.args = {
      inherit notnft;
    };
    inherit notnft;
  };
  options.notnft = (builtins.mapAttrs (k: v: lib.mkOption { type = lib.types.unspecified; readOnly = true; }) config.notnft) // {
    enumMode = lib.mkOption {
      default = "normal";
      type = lib.types.str;
      description = lib.mdDoc ''
        Enum mode. "strict" to disallow using strings, "normal" for default behavior, "lax" to disable enum checks.
      '';
    };
  };
}
